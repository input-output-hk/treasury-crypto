package io.iohk.protocol.keygen_him

import io.iohk.core.crypto.encryption.{KeyPair, PubKey}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.common.commitment.PedersenCommitment
import io.iohk.protocol.common.datastructures.Share
import io.iohk.protocol.common.him.HIM
import io.iohk.protocol.common.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.common.secret_sharing.ShamirSecretSharing.{IdPointMap, SharingParameters, decryptShares, encryptShares, getShares, shareIsValid}
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.CorrectSharing
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.CorrectSharing.{Statement, Witness}
import io.iohk.protocol.keygen_him.datastructures.{R1Data, R2Data, R3Data, R4Data}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.dlog_encryption.NIZKs.CorrectDecryptionNIZK.CorrectDecryption
import io.iohk.protocol.resharing.datastructures.{Complaint, DealersShare}

import scala.collection.mutable.ArrayBuffer

case class DKGenerator(context:    CryptoContext,
                       crs:        Seq[GroupElement],
                       ownKeyPair: KeyPair,
                       allPubKeys: Seq[PubKey],
                       alphas:     Seq[BigInt],
                       betas:      Seq[BigInt]) {
  assert(crs.nonEmpty)
  assert(allPubKeys.nonEmpty)
  assert(alphas.length == allPubKeys.length) // number of alphas is the same as the total number of parties
  // The number of betas implicitly defines the number of global public keys to be generated
  // It also should be (n - t); thus for the adversarial threshold t = n/2 - 1, the maximal number of generated keys is n/2 + 1
  assert(betas.nonEmpty && (betas.length == alphas.length / 2 + 1))
  assert(allPubKeys.contains(ownKeyPair._2)) // own key-pair should be among the participating parties keys

  private val params = SharingParameters(allPubKeys)
  val partialSK = context.group.createRandomNumber
  private val polynomial = Polynomial(context.group, params.t - 1, partialSK)

  implicit private val group: DiscreteLogGroup = context.group
  private val g = group.groupGenerator
  private val h = crs.head
  private val commitment = PedersenCommitment(g, h)
  val ownID = params.keyToIdMap.getId(ownKeyPair._2).get
  val ownEvalPoint = BigInt(IdPointMap.toPoint(ownID))

  private var receivedShares = ArrayBuffer[DealersShare]() // sorted by a senderID (SenderID, share-value) tuples for QUAL members
  private var partialSKs = ArrayBuffer[BigInt]() // actually the shares of the global SKs computed by multiplication with HIM
  private var coeffsCommitments = ArrayBuffer[(Int, Seq[GroupElement])]() // sorted by a senderID sets of VALID commitments of all polynomial coefficients (g^a_i) received from parties in QUAL

  var qualifiedSet = Set[Int]() // QUAL set of parties (parties identifiers)

  private val r1DataQual = ArrayBuffer[R1Data]() // R1Data sent in Round 1 by the all qualified parties
  private val r2DataQual = ArrayBuffer[R2Data]() // R2Data sent in Round 2 by the all qualified parties

  def getPartialSKs: Seq[BigInt] = {
    partialSKs
  }

  // Round to distribute shares of the own partial secret
  //   together with Pedersen commitments of coefficients of the polynomial that was used to create the shares
  def round1(): R1Data = {
    val c_rand = polynomial.coeffs().map(c => (c, group.createRandomNumber))
    val C = c_rand.map{ case(c, r) => commitment.get(c, r) }

    val shares = getShares(polynomial, params.allIds.map(IdPointMap.toPoint))
    val encShares_rand = encryptShares(context, shares, params)

    val encShares = encShares_rand.map(_._1)
    val sharesRandomness = encShares_rand.map(_._2)

    val proof = CorrectSharing(
      h,
      allPubKeys,
      Statement(C, encShares)
    ).prove(
      Witness(
        shares.zip(sharesRandomness.map(_.R)), c_rand.map(_._2)
      )
    )
    R1Data(ownID, encShares, C, proof)
  }

  // Round to validate posted shares,
  //       to create QUAL set based on the valid shares,
  //       to post commitments of the own polynomial coefficients
  def round2(r1DataAll: Seq[R1Data]): R2Data = {
    assert(r1DataAll.size <= params.n) // the number of posted R1Data-messages can't exceed the total number of parties

    // Checking that all R1Data-messages are from different parties
    assert(r1DataAll.map(_.senderID).distinct.length == r1DataAll.length)

    // Creating QUAL set of the parties who provided valid shares in the 1-st round
    r1DataAll.foreach{d =>
      if(CorrectSharing(
         h, allPubKeys,
         Statement(d.coeffsCommitments, d.encShares)
         ).verify(d.proofNIZK)){
        qualifiedSet = qualifiedSet + d.senderID
      }
    }

    assert(r1DataQual.isEmpty)

    // Filtering away the R1Data-messages from disqualified members
    r1DataQual ++= r1DataAll.filter(d => qualifiedSet.contains(d.senderID))

    val senderID_encShare = r1DataQual.map{ d =>
      // All shares posted by each party should be for different receiving parties
      assert(d.encShares.map(_.receiverID).distinct.size == d.encShares.size)
      // Take the encrypted share for own ID
      (d.senderID, d.encShares.filter(_.receiverID == ownID).head)
    }

    val senderIDs = senderID_encShare.map(_._1)
    val encShares = senderID_encShare.map(_._2)

    assert(receivedShares.isEmpty)
    receivedShares ++=
      senderIDs.zip(decryptShares(context, encShares, ownKeyPair._1).get.map(_.value))
      .map{case(dealerId, share) => DealersShare(dealerId, share)}
      .sortBy(_.dealerID)

    val him = HIM(alphas.take(receivedShares.size), betas)
    assert(partialSKs.isEmpty)
    partialSKs ++= him.mul(receivedShares.map(_.openedShare))

    val D = polynomial.coeffs().map(c => commitment.get(c, BigInt(0)))
    R2Data(ownID, D)
  }

  // Round to validate the committed coefficients
  //   and to post complaints if some commitments are inconsistent with corresponding shares
  def round3(r2DataAll: Seq[R2Data]): Option[R3Data] = {
    // Checking that all R2Data-messages are from different parties
    assert(r2DataAll.map(_.senderID).distinct.length == r2DataAll.length)

    assert(r2DataQual.isEmpty)
    // Filtering away the R2Data-messages from disqualified parties
    r2DataQual ++= r2DataAll.filter(d => qualifiedSet.contains(d.senderID))

    val complaints = r2DataQual
      .flatMap{d =>
        val dealersShare = receivedShares.find(_.dealerID == d.senderID).get
        if (!shareIsValid(context, params.t, Share(ownEvalPoint.toInt, dealersShare.openedShare), d.coeffsCommitments)){
          // Removing the misbehaving party from the QUAL set
          qualifiedSet = qualifiedSet - d.senderID
          // Creating complaint on the party
          Some(createComplaint(dealersShare))
        } else {
          coeffsCommitments += Tuple2(d.senderID, d.coeffsCommitments)
          None
        }
    }

    if(complaints.nonEmpty){
      Some(R3Data(ownID, complaints))
    } else {
      // Sort all sets of received commitments by IDs of their senders
      coeffsCommitments = coeffsCommitments.sortBy(_._1)
      None
    }
  }

  // Round to reconstruct partial secrets of disqualified dealers
  //   and to post a set of Global Public Keys
  //   (GPKs are generated by multiplying HIM by the vector of commitments of a_0 coefficients (g^a_0) of all parties qualified in round 2)
  def round4(r3DataAll: Seq[R3Data]): R4Data = {
    // Checking that all R3Data-messages are from different parties
    assert(r3DataAll.map(_.senderID).distinct.length == r3DataAll.length)

    val r3DataQualified = r3DataAll
      .filter(d => qualifiedSet.contains(d.senderID)) // Filtering away the R3Data-messages from disqualified parties
      .filter{d =>                                    // Filtering away the parties who provided at least one invalid complaint
        val allComplaintsAreValid = d.complaints.forall(complaintIsValid(d.senderID, _))
        // Disqualifying the party that posted an invalid complaint
        if(!allComplaintsAreValid){ qualifiedSet = qualifiedSet - d.senderID }
        allComplaintsAreValid
      }

    val disqualifiedDealers = r3DataQualified.headOption match {
      case Some(head) => head.complaints.map(_.share.dealerID).distinct.sorted
      case None => Seq() // r3DataQualified is empty if no complaints where posted in round 3
    }

    assert(
      r3DataQualified.forall{d =>
        val dealersIds = d.complaints.map(_.share.dealerID)
        dealersIds.distinct.length == dealersIds.length && // complaints provided by each party are all for unique dealers
          dealersIds.sorted == disqualifiedDealers   // each party has provided complaints for the same set of disqualified dealers
      }
    )

    if (r3DataQualified.nonEmpty){ // r3DataQualified is empty when there are no misbehaving parties
      require(r3DataQualified.length >= params.t, "Insufficient number of complaints(shares) for reconstruction")
    }

    // Shares are grouped by the disqualified dealers' IDs
    val disqualifiedDealersShares = disqualifiedDealers.map(id =>
      (
        id, r3DataQualified.map{ d =>
          val complaint = d.complaints.filter(_.share.dealerID == id)
          assert(complaint.length == 1)
          Share(IdPointMap.toPoint(d.senderID), complaint.head.share.openedShare)
        }
      )
    )

    // Reconstructed polynomials of disqualified dealers
    val disqualifiedDealersPolynomials = disqualifiedDealersShares.map{
      case(id, shares) =>
        val points_values = shares.map(share => (BigInt(share.point), share.value)).take(params.t)
        (id, LagrangeInterpolation.interpolate(points_values))
    }

    // Lifting polynomials' coefficients (g^c_i) to obtain commitments
    val disqualifiedDealersCoeffsCommitments = disqualifiedDealersPolynomials.map{
      case(id, polynomial) => (id, polynomial.coeffs().map(c => commitment.get(c, BigInt(0))))
    }

    // Adding reconstructed commitments to the overall list of commitments
    coeffsCommitments ++= disqualifiedDealersCoeffsCommitments
    // Sorting all commitments by sender's (dealer's) Id
    coeffsCommitments = coeffsCommitments.sortBy(_._1)

    assert(coeffsCommitments.length == receivedShares.length)

    // Computing the Global Public Keys
    val him = HIM(alphas.take(receivedShares.size), betas)
    // Multiplying HIM by a vector of a0-commitments of each party
    val gpks = him.mulLifted(coeffsCommitments.map(_._2.head))

    R4Data(ownID, gpks)
  }

  def createComplaint(share: DealersShare): Complaint = {
    val encShare =
      r1DataQual.find(_.senderID == share.dealerID).get // set of shares distributed by a specific dealer
      .encShares.find(_.receiverID == ownID).get // share of the complaining party

    val st = CorrectDecryption.Statement(ownKeyPair._2, share.openedShare, encShare.S)
    val w = CorrectDecryption.Witness(ownKeyPair._1)

    Complaint(share, CorrectDecryption(st).prove(w))
  }

  def complaintIsValid(complaintSenderId: Int, complaint: Complaint): Boolean = {
    val pk = params.keyToIdMap.getPubKey(complaintSenderId).get
    val encShare =
      r1DataQual.find(_.senderID == complaint.share.dealerID).get // set of shares distributed by a specific dealer
      .encShares.find(_.receiverID == complaintSenderId).get // share of the complaining party

    val st = CorrectDecryption.Statement(pk, complaint.share.openedShare, encShare.S)
    val dealersR2Data = r2DataQual.find(_.senderID == complaint.share.dealerID).get

    !shareIsValid(context, params.t, Share(IdPointMap.toPoint(complaintSenderId), complaint.share.openedShare), dealersR2Data.coeffsCommitments) &&
      CorrectDecryption(st).verify(complaint.proof)
  }
}