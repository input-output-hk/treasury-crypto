package treasury.crypto.keygen

import java.math.BigInteger

import org.bouncycastle.math.ec.ECPoint
import treasury.crypto.core._
import treasury.crypto.keygen.datastructures.round1.{R1Data, SecretShare}
import treasury.crypto.keygen.datastructures.round2.{ComplaintR2, R2Data, ShareProof}
import treasury.crypto.keygen.datastructures.round3.R3Data
import treasury.crypto.keygen.datastructures.round4.{ComplaintR4, OpenedShare, R4Data}
import treasury.crypto.keygen.datastructures.round5_1.R5_1Data
import treasury.crypto.keygen.datastructures.round5_2.{R5_2Data, SecretKey}
import treasury.crypto.nizk.ElgamalDecrNIZK
import treasury.crypto.keygen.DistrKeyGen.{checkOnCRS, checkComplaintR2, checkCommitmentR3 }

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

// Distributed Key Generation, based on Elliptic Curves
//
class DistrKeyGen(cs:               Cryptosystem,     // cryptosystem, which should be used for protocol running
                  h:                Point,            // CRS parameter
                  transportKeyPair: KeyPair,          // key pair for shares encryption/decryption
                  membersPubKeys:   Seq[PubKey],      // public keys of all protocol members, including own public key from transportKeyPair
                  memberIdentifier: Identifier[Int])  // generator of members identifiers, based on the list of members public keys (membersPubKeys)
{
  private val CRS_commitments = new ArrayBuffer[CRS_commitment]() // CRS commitments of other participants
  private val commitments     = new ArrayBuffer[Commitment]()     // Commitments of other participants
  private val shares          = new ArrayBuffer[Share]()          // Shares of other participants
  private val violatorsIDs    = new ArrayBuffer[Integer]()        // ID's of members-violators (absent on the 1-st round, and those, who supplied incorrect commitments on rounds 1 and 3)
  private val absenteesIDs    = new ArrayBuffer[Integer]()        // ID's of members who were absent on round 3, so their secrets should be reconstructed

  private val n = membersPubKeys.size           // Total number of protocol participants
          val t = (n.toFloat / 2).ceil.toInt    // Threshold number of participants
  private val A = new Array[ECPoint](t)         // Own commitments

  private val g = cs.basePoint
  private val infinityPoint = cs.infinityPoint

  private val ownPrivateKey = transportKeyPair._1
  private val ownPublicKey  = transportKeyPair._2.normalize()
  private val allMembersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
          val ownID: Integer = memberIdentifier.getId(ownPublicKey).get

          val roundsDataCache = RoundsData()
  private var roundsPassed: Int = 0
  def getRoundsPassed: Int = roundsPassed


  def getShare(id: Integer): Option[BigInteger] = {

    val shareOpt = shares.find(_.issuerID == id)
    shareOpt match {
      case Some(share) => Some(new BigInteger(share.share_a.S.decryptedMessage))
      case None => None
    }
  }

  /**
    * Executes the 1-st round of the DKG protocol.
    *
    * Generates random polynomials, CRS commitments for both of them and secret shares for the 0-th coefficient of the each polynomial.
    * In the first polynomial (poly_a) the 0-th coefficient is the supplied secret key.
    *
    * Generated data is placed into the R1Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR1Data) is supplied, the check for identity of generated R1Data and prevR1Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR1Data and newly generated R1Data are inconsistent and None is returned, the generated R1Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R1Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param secretKey secret key (own private key), which will be used for generation of the shared public key
    * @param prevR1Data optional, R1data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R1Data) if success, None otherwise
    */
  def doRound1(secretKey: Array[Byte], prevR1Data: Option[R1Data] = None): Option[R1Data] = {

    roundsPassed match {
      case 1 => return roundsDataCache.r1Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 0) => return None // Round should be executed strictly after the previous round
      case 0 =>
    }

    val poly_a = new Polynomial(cs, new BigInteger(secretKey), t)
    val poly_b = new Polynomial(cs, new BigInteger(secretKey), t)

    for(i <- A.indices)
      A(i) = g.multiply(poly_a(i)).normalize()

    val E   = new ArrayBuffer[Array[Byte]]()
    val S_a = new ArrayBuffer[SecretShare]()
    val S_b = new ArrayBuffer[SecretShare]()

    // CRS commitments for each coefficient of both polynomials
    for(i <- A.indices)
      E += A(i).add(h.multiply(poly_b(i))).normalize().getEncoded(true)

    for(i <- membersPubKeys.indices)
    {
      val receiverPublicKey = membersPubKeys(i)

      if(receiverPublicKey != ownPublicKey)
      {
        val recipientID = memberIdentifier.getId(receiverPublicKey).get
        val x = recipientID + 1

        assert(x != 0) // avoid share for a_0 coefficient

        S_a += SecretShare(recipientID, cs.hybridEncrypt(receiverPublicKey, poly_a.evaluate(x).toByteArray, ownPrivateKey.toByteArray))
        S_b += SecretShare(recipientID, cs.hybridEncrypt(receiverPublicKey, poly_b.evaluate(x).toByteArray, ownPrivateKey.toByteArray))
      }
    }
    val r1Data = R1Data(ownID, E.toArray, S_a.sortBy(_.receiverID).toArray, S_b.sortBy(_.receiverID).toArray)

    roundsPassed += 1
    roundsDataCache.r1Data = Seq(r1Data) // round output is always cached

    // Check if the current round output is equal to data from previous execution
    // If not - the current round output can be taken from cache
    prevR1Data match {
      case Some(data) =>
        val prevR1DataSorted = R1Data(data.issuerID, data.E, data.S_a.sortBy(_.receiverID), data.S_b.sortBy(_.receiverID))
        prevR1DataSorted match {
          case prevData if !prevData.equals(r1Data) => None
          case _ => Some(r1Data)
        }
      case None => Some(r1Data)
    }
  }

  /**
    * Executes the 2-nd round of the DKG protocol.
    *
    * Verifies 1-st round CRS commitments supplied by other members (placed in R1Data) and creates complaints on those of them, who's data is incorrect.
    * The members, who has supplied incorrect 1-st round commitments, are listed as violators and will be ignored during the further protocol execution.
    * In the same way the members, who hasn't supplied any commitments, are treated.
    *
    * Created complaints (if any) are placed into the R2Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR2Data) is supplied, the check for identity of generated R2Data and prevR2Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR2Data and newly generated R2Data are inconsistent and None is returned, the generated R2Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R2Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r1Data a sequence of R1Data packets of all protocol members (including the own one)
    * @param prevR2Data optional, R2data from a previous execution of this round (should be passed during internal state restoring)
    * @return Some(R2Data) if success, None otherwise
    */
  def doRound2(r1Data: Seq[R1Data], prevR2Data: Option[R2Data] = None): Option[R2Data] = {

    roundsPassed match {
      case 2 => return roundsDataCache.r2Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 1) => return None // Round should be executed strictly after the previous round
      case 1 =>
    }

    var complaints = new ArrayBuffer[ComplaintR2]()

    for(i <- r1Data.indices) {
      assert(r1Data(i).S_a.length == r1Data(i).S_b.length)

      for(j <- r1Data(i).S_a.indices) {
        if(r1Data(i).S_a(j).receiverID == ownID) {
          val secretShare_a = r1Data(i).S_a(j)
          val secretShare_b = r1Data(i).S_b(j)

          val openedShare_a = OpenedShare(secretShare_a.receiverID, cs.hybridDecrypt(ownPrivateKey, secretShare_a.S))
          val openedShare_b = OpenedShare(secretShare_b.receiverID, cs.hybridDecrypt(ownPrivateKey, secretShare_b.S))

          if(checkOnCRS(cs, h, openedShare_a, openedShare_b, r1Data(i).E)) {
            shares += Share(r1Data(i).issuerID, openedShare_a, openedShare_b)
            CRS_commitments += CRS_commitment(r1Data(i).issuerID, r1Data(i).E.map(x => cs.decodePoint(x)))
          }
          else {
            val proof_a = ElgamalDecrNIZK.produceNIZK(cs, secretShare_a.S.encryptedKey, ownPrivateKey)
            val proof_b = ElgamalDecrNIZK.produceNIZK(cs, secretShare_b.S.encryptedKey, ownPrivateKey)

            complaints += ComplaintR2(
              r1Data(i).issuerID,
              ownPublicKey,
              ShareProof(secretShare_a.S, openedShare_a.S, proof_a),
              ShareProof(secretShare_b.S, openedShare_b.S, proof_b))

            violatorsIDs += r1Data(i).issuerID
          }
        }
      }
    }

    // Avoid participation of absent members in further rounds
    val activeMembers = r1Data.map(_.issuerID)
    val absentMembers = allMembersIDs.diff(activeMembers)
    absentMembers.foreach(x => violatorsIDs += x)

    // Sort complaints array for ability to compare R2Data to each other
    val r2Data = R2Data(ownID, complaints.sortBy(_.violatorID).toArray)

    roundsPassed += 1
    roundsDataCache.r2Data = Seq(r2Data) // round output is always cached

    prevR2Data match {
      case Some(data) =>
        val prevR2DataSorted = R2Data(data.issuerID, data.complaints.sortBy(_.violatorID))
        prevR2DataSorted match {
          case prevData if !prevData.equals(r2Data) => None
          case _ => Some(r2Data)
        }
      case None => Some(r2Data)
    }
  }

  /**
    * Executes the 3-rd round of the DKG protocol.
    *
    * Checks complaints from non-disqualified members, contained in r2DataIn.
    * In case of at least one valid complaint, the corresponding member is listed as a protocol violator and his shares and commitments from the round 1 are deleted. Such a member will be ignored during the further protocol execution.
    * Posts own commitments of the poly_a coefficients (commitments are placed into the R3Data structure).
    *
    * The R3Data structure should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR3Data) is supplied, the check for identity of generated R3Data and prevR3Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR3Data and newly generated R3Data are inconsistent and None is returned, the generated R3Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R3Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r2DataIn a sequence of R2Data packets of all protocol members (including the own one).
    * @param prevR3Data optional, R3data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R3Data) if success, None otherwise
    */
  def doRound3(r2DataIn: Seq[R2Data], prevR3Data: Option[R3Data] = None): Option[R3Data] = {

    roundsPassed match {
      case 3 => return roundsDataCache.r3Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 2) => return None // Round should be executed strictly after the previous round
      case 2 =>
    }

    // Ignore messages from disqualified members
    val r2Data = r2DataIn.filter(x => !violatorsIDs.contains(x.issuerID))

    // Remove received shares and commitments of disqualified members (if they were verified successfully, but at least 1 complaint on their issuer was received)
    for(i <- r2Data.indices) {
      for(j <- r2Data(i).complaints.indices) {
        val complaint = r2Data(i).complaints(j)
        val violatorID = complaint.violatorID

        if(violatorID != ownID &&
           checkComplaintR2(cs, complaint)) {

          val violatorCRSCommitment = CRS_commitments.find(_.issuerID == violatorID)
          if(violatorCRSCommitment.isDefined)
            CRS_commitments -= violatorCRSCommitment.get

          val violatorShare = shares.find(_.issuerID == violatorID)
          if(violatorShare.isDefined)
            shares -= violatorShare.get

          if(!violatorsIDs.contains(violatorID))
            violatorsIDs += violatorID
        }
      }
    }

    // Commitments of poly_a coefficients
    val r3Data = R3Data(ownID, A.map(_.getEncoded(true)))

    roundsPassed += 1
    roundsDataCache.r3Data = Seq(r3Data) // round output is always cached

    prevR3Data match {
      case Some(data) =>
        data match {
          case prevData if !prevData.equals(r3Data) => None
          case _ => Some(r3Data)
        }
      case None => Some(r3Data)
    }
  }

  /**
    * Executes the 4-th round of the DKG protocol.
    *
    * Verifies 3-rd round commitments supplied by other members (placed in R3Data) and creates complaints on those of them, who's data is incorrect.
    * The members, who has supplied incorrect 3-rd round commitments, are listed as violators and will be ignored during the further protocol execution.
    * The members, who hasn't supplied any 3-rd round commitments, are listed as absentees, and their secret keys will be reconstructed during rounds 5_1, 5_2. Absentees will also be ignored during the further protocol execution.
    *
    * Created complaints (if any) are placed into the R4Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR4Data) is supplied, the check for identity of generated R4Data and prevR4Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR4Data and newly generated R4Data are inconsistent and None is returned, the generated R4Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R4Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r3DataIn a sequence of R3Data packets of all protocol members (including the own one).
    * @param prevR4Data optional, R4Data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R4Data) if success, None otherwise
    */
  def doRound4(r3DataIn: Seq[R3Data], prevR4Data: Option[R4Data] = None): Option[R4Data] = {

    roundsPassed match {
      case 4 => return roundsDataCache.r4Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 3) => return None // Round should be executed strictly after the previous round
      case 3 =>
    }

    // Ignore messages from disqualified members
    val r3Data = r3DataIn.filter(x => !violatorsIDs.contains(x.issuerID))

    var complaints = new ArrayBuffer[ComplaintR4]()

    for(i <- r3Data.indices) {
      val issuerID = r3Data(i).issuerID
      val issuerCommitments = r3Data(i).commitments

      if(issuerID != ownID) {

        val share = shares.find(_.issuerID == issuerID)
        if(share.isDefined) {

          if(checkCommitmentR3(cs, share.get, issuerCommitments)) {
            commitments += Commitment(issuerID, issuerCommitments.map(cs.decodePoint))
          } else {
            complaints += ComplaintR4(issuerID, share.get.share_a, share.get.share_b)
            violatorsIDs += issuerID
          }
        } //if(!share.isDefined) is the case, when a member is disqualified, and his shares are already deleted from the local state of the current member
      }
    }

    // Members, who hasn't supplied 3-rd round data, are absentees, who's secret keys should be restored for ability to get their individual public key
    val activeMembers = r3Data.map(_.issuerID)
    val absentMembers = allMembersIDs.diff(activeMembers) // violators and absentees
    absentMembers.foreach(id => if(!violatorsIDs.contains(id)) absenteesIDs += id)

    val r4Data = R4Data(ownID, complaints.sortBy(_.violatorID).toArray)

    roundsPassed += 1
    roundsDataCache.r4Data = Seq(r4Data) // round output is always cached

    prevR4Data match {
      case Some(data) =>
        val prevR4DataSorted = R4Data(data.issuerID, data.complaints.sortBy(_.violatorID))
        prevR4DataSorted match {
          case prevData if !prevData.equals(r4Data) => None
          case _ => Some(r4Data)
        }
      case None => Some(r4Data)
    }
  }

  /**
    * Executes the 5.1-st round of the DKG protocol.
    *
    * Checks complaints from non-disqualified members, contained in r4DataIn.
    * In case of at least one valid complaint, the violator's opened share (decrypted secret share, received from round 1) is posted. The corresponding member is also listed as a protocol violator and will be ignored during the further protocol execution.
    * Opened shares of the 3-rd round absentees are also posted.
    *
    * Shares to be posted are placed into the R5_1Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR5_1Data) is supplied, the check for identity of generated R5_1Data and prevR5_1Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR5_1Data and newly generated R5_1Data are inconsistent and None is returned, the generated R5_1Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R5_1Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r4DataIn a sequence of R4Data packets of all protocol members (including the own one).
    * @param prevR5_1Data optional, R5_1Data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R5_1Data) if success, None otherwise
    */
  def doRound5_1(r4DataIn: Seq[R4Data], prevR5_1Data: Option[R5_1Data] = None): Option[R5_1Data] = {

    def checkComplaint(violatorsCommitment: Commitment, complaint: ComplaintR4): Boolean = {
      val violatorsCRSCommitment = CRS_commitments.find(_.issuerID == complaint.violatorID).get
      val CRS_Ok = checkOnCRS(cs, h, complaint.share_a, complaint.share_b, violatorsCRSCommitment.crs_commitment.map(_.getEncoded(true)))

      val share = Share(complaint.violatorID, complaint.share_a, complaint.share_b)
      val Commitment_Ok = checkCommitmentR3(cs, share, violatorsCommitment.commitment.map(_.getEncoded(true)))

      CRS_Ok && !Commitment_Ok
    }

    roundsPassed match {
      case 5 => return roundsDataCache.r5_1Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 4) => return None // Round should be executed strictly after the previous round
      case 4 =>
    }

    val violatorsShares = ArrayBuffer[(Integer, OpenedShare)]()

    val r4Data = r4DataIn.filter(x => {
      !violatorsIDs.contains(x.issuerID) &&
      !absenteesIDs.contains(x.issuerID)})

    for(i <- r4Data.indices) {
      for(j <- r4Data(i).complaints.indices) {
        val violatorID = r4Data(i).complaints(j).violatorID

        if(violatorID != ownID &&
          !violatorsShares.exists(_._1 == violatorID)) {

          val violatorShare = shares.find(_.issuerID == violatorID)
          val violatorCommitment = commitments.find(_.issuerID == violatorID)

          if(violatorCommitment.isDefined) {
            if(checkComplaint(violatorCommitment.get, r4Data(i).complaints(j))) {
              if(violatorShare.isDefined)
                violatorsShares += Tuple2(violatorID, violatorShare.get.share_a)

              // Deleting commitment A of the violator
              commitments -= violatorCommitment.get

              if(!violatorsIDs.contains(violatorID))
                violatorsIDs += violatorID
            }
          }
          else if(violatorShare.isDefined) {
            // Commitment of the violator is absent, because it wasn't accepted on the round 4. So just post the share of the violator.
            violatorsShares += Tuple2(violatorID, violatorShare.get.share_a)
          }
        }
      }
    }

    // Post shares for 3-rd round absentees, as their keys also should be reconstructed
    absenteesIDs.foreach(absenteeID => {
      val absenteeShare = shares.find(_.issuerID == absenteeID)
      if(absenteeShare.isDefined)
        violatorsShares += Tuple2(absenteeID, absenteeShare.get.share_a)
    })

    val r5_1Data = R5_1Data(ownID, violatorsShares.sortBy(_._1).toArray)

    roundsPassed += 1
    roundsDataCache.r5_1Data = Seq(r5_1Data) // round output is always cached

    prevR5_1Data match {
      case Some(data) =>
        val prevR5_1DataSorted = R5_1Data(data.issuerID, data.violatorsShares.sortBy(_._1))
        prevR5_1DataSorted match {
          case prevData if !prevData.equals(r5_1Data) => None
          case _ => Some(r5_1Data)
        }
      case None => Some(r5_1Data)
    }
  }

  /**
    * Executes the 5.2-nd round of the DKG protocol.
    *
    * Gathers shares of disqualified members, which has been posted by all protocol members in R5_1Data.
    * Using gathered shares reconstructs secrets of disqualified members and obtains their individual public keys.
    * Using the round 3 commitments of present members and reconstructed public keys of disqualified members obtains a common shared public key.
    *
    * Reconstructed secret keys and shared public key are placed into the R5_2Data structure.
    * When a data from the previous execution of this round (prevR5_2Data) is supplied, the check for identity of generated R5_2Data and prevR5_2Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR5_2Data and newly generated R5_2Data are inconsistent and None is returned, the generated R5_2Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R5_2Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r5_1DataIn a sequence of R5_1Data packets of all protocol members (including the own one).
    * @param prevR5_2Data optional, R5_2Data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R5_2Data) if success, None otherwise
    */
  def doRound5_2(r5_1DataIn: Seq[R5_1Data], prevR5_2Data: Option[R5_2Data] = None): Option[R5_2Data] = {

    roundsPassed match {
      case 6 => return roundsDataCache.r5_2Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 5) => return None // Round should be executed strictly after the previous round
      case 5 =>
    }

    val violatorsShares = new ArrayBuffer[ViolatorShare]

    val r5_1Data = r5_1DataIn.filter(x => {
      !violatorsIDs.contains(x.issuerID) &&
      !absenteesIDs.contains(x.issuerID)})

    // Retrieving shares of each violator
    for(i <- r5_1Data.indices) {
      for(j <- r5_1Data(i).violatorsShares.indices) {
        val violatorID = r5_1Data(i).violatorsShares(j)._1

        if(violatorID != ownID) {
          val violatorShare = r5_1Data(i).violatorsShares(j)._2

          if(violatorsShares.exists(_.violatorID == violatorID))
            violatorsShares.find(_.violatorID == violatorID).get.violatorShares += violatorShare
          else
            violatorsShares += ViolatorShare(violatorID, new ArrayBuffer[OpenedShare]() += violatorShare)
        }
      }
    }

    val violatorsSecretKeys = for(i <- violatorsShares.indices) yield {
      SecretKey(violatorsShares(i).violatorID, LagrangeInterpolation.restoreSecret(cs, violatorsShares(i).violatorShares, t).toByteArray)
    }

    val violatorsPublicKeys = for(i <- violatorsSecretKeys.indices) yield {
      g.multiply(new BigInteger(violatorsSecretKeys(i).secretKey))
    }

    var honestPublicKeysSum = A(0) // own public key
    for(i <- commitments.indices) {
      honestPublicKeysSum = honestPublicKeysSum.add(commitments(i).commitment(0))
    }

    var violatorsPublicKeysSum: ECPoint = cs.infinityPoint
    for(i <- violatorsPublicKeys.indices) {
      violatorsPublicKeysSum = violatorsPublicKeysSum.add(violatorsPublicKeys(i))
    }

    val sharedPublicKey = honestPublicKeysSum.add(violatorsPublicKeysSum)

    val r5_2Data = R5_2Data(ownID, sharedPublicKey.getEncoded(true), violatorsSecretKeys.sortBy(_.ownerID).toArray)

    roundsPassed += 1
    roundsDataCache.r5_2Data = Seq(r5_2Data) // round output is always cached

    prevR5_2Data match {
      case Some(data) =>
        val prevR5_2DataSorted = R5_2Data(data.issuerID, data.sharedPublicKey, data.violatorsSecretKeys.sortBy(_.ownerID))
        prevR5_2DataSorted match {
          case prevData if !prevData.equals(r5_2Data) => None
          case _ => Some(r5_2Data)
        }
      case None => Some(r5_2Data)
    }
  }

  /**
    * Restores internal state up to a certain round of the DKG protocol.
    *
    * Sequentially executes the DKG round functions, depending on available data from previously executed rounds.
    * Round function can be executed, if data from previous round and own data for current round is available in roundsData.
    * Availability of an own data in a certain round means, that round has been already locally executed, thus the local DKG state should be accordingly modified.
    *
    * NOTE (for usage in the DLT systems):
    * When collecting roundsData, in the incomplete round the own data should be searched in mempool as well as in history.
    *
    * @param secretKey secret key (own private key), which will be used for generation of the shared public key
    * @param roundsData data of all protocol members for the all rounds, which has been already executed
    * @return Success(Some(SharedPublicKey)) if all 6 rounds has been executed successfully;
    *         Success(None) if not all 6 rounds has been executed, and execution should be continued after state restoring;
    *         Failure(e)    if an error during state restoring has occurred (mainly because of inconsistency of newly generated and previously obtained own round data).
    */
  def setState(secretKey: Array[Byte], roundsData: RoundsData): Try[Option[SharedPublicKey]] = Try {

    var sharedPubKey: Option[SharedPublicKey] = None

    val ownRound1Data = roundsData.r1Data.find(_.issuerID == ownID)
    val ownRound2Data = roundsData.r2Data.find(_.issuerID == ownID)
    val ownRound3Data = roundsData.r3Data.find(_.issuerID == ownID)
    val ownRound4Data = roundsData.r4Data.find(_.issuerID == ownID)
    val ownRound5_1Data = roundsData.r5_1Data.find(_.issuerID == ownID)
    val ownRound5_2Data = roundsData.r5_2Data.find(_.issuerID == ownID)

    if (ownRound1Data.isDefined)
    {
      val r1Data = doRound1(secretKey, ownRound1Data)
      require(r1Data.isDefined, "r1Data != ownRound1Data")

      if (ownRound2Data.isDefined && roundsData.r1Data.nonEmpty)
      {
        val r2Data = doRound2(roundsData.r1Data, ownRound2Data)
        require(r2Data.isDefined, "r2Data != ownRound2Data")

        if (ownRound3Data.isDefined && roundsData.r2Data.nonEmpty)
        {
          val r3Data = doRound3(roundsData.r2Data, ownRound3Data)
          require(r3Data.isDefined, "r3Data != ownRound3Data")

          if (ownRound4Data.isDefined && roundsData.r3Data.nonEmpty)
          {
            val r4Data = doRound4(roundsData.r3Data, ownRound4Data)
            require(r4Data.isDefined, "r3Data != ownRound4Data")

            if (ownRound5_1Data.isDefined && roundsData.r4Data.nonEmpty)
            {
              val r5_1Data = doRound5_1(roundsData.r4Data, ownRound5_1Data)
              require(r5_1Data.isDefined, "r5_1Data != ownRound5_1Data")

              if (ownRound5_2Data.isDefined && roundsData.r5_1Data.nonEmpty)
              {
                val r5_2Data = doRound5_2(roundsData.r5_1Data, ownRound5_2Data)
                require(r5_2Data.isDefined, "r5_2Data != ownRound5_2Data")

                sharedPubKey = Some(r5_2Data.get.sharedPublicKey)
              }
            }
          }
        }
      }
    }
    sharedPubKey
  }
}

object DistrKeyGen {

  private def checkOnCRS(cs: Cryptosystem,
                         h: Point,
                         share_a: OpenedShare,
                         share_b: OpenedShare,
                         E: Array[Array[Byte]]): Boolean = {

    var E_sum: ECPoint = cs.infinityPoint

    for(i <- E.indices) {
      E_sum = E_sum.add(cs.decodePoint(E(i)).multiply(BigInteger.valueOf(share_a.receiverID.toLong + 1).pow(i)))
    }
    val CRS_Shares = cs.basePoint.multiply(new BigInteger(share_a.S.decryptedMessage)).add(h.multiply(new BigInteger(share_b.S.decryptedMessage)))

    CRS_Shares.equals(E_sum)
  }

  def checkComplaintR2(cs: Cryptosystem,
                       complaint: ComplaintR2): Boolean = {

    def checkProof(pubKey: PubKey, proof: ShareProof): Boolean = {
      ElgamalDecrNIZK.verifyNIZK(
        cs,
        pubKey,
        proof.encryptedShare.encryptedKey,
        proof.decryptedShare.decryptedKey,
        proof.NIZKProof)
    }

    def checkEncryption(proof: ShareProof): Boolean = {
      val ciphertext = cs.hybridEncrypt(
        cs.infinityPoint,                     // for this verification no matter what public key is used
        proof.decryptedShare.decryptedMessage,
        Array.fill(32)(1.toByte),             // for this verification no matter what secret seed is used
        Some(proof.decryptedShare.decryptedKey))

      ciphertext.encryptedMessage.sameElements(proof.encryptedShare.encryptedMessage)
    }

    val publicKey = complaint.issuerPublicKey
    val proof_a = complaint.shareProof_a
    val proof_b = complaint.shareProof_b

    (checkProof(publicKey, proof_a) && checkEncryption(proof_a)) &&
      (checkProof(publicKey, proof_b) && checkEncryption(proof_b))
  }

  def checkCommitmentR3(cs: Cryptosystem,
                        share: Share,
                        commitment: Array[Array[Byte]]): Boolean = {

    val A = commitment.map(cs.decodePoint)
    val X = BigInteger.valueOf(share.share_a.receiverID.toLong + 1)

    var A_sum: ECPoint = cs.infinityPoint

    for(i <- A.indices) {
      A_sum = A_sum.add(A(i).multiply(X.pow(i)))
    }

    val share_a = new BigInteger(share.share_a.S.decryptedMessage)
    val g_sa = cs.basePoint.multiply(share_a)

    g_sa.equals(A_sum)
  }

  /**
    * Calculates a shared public key, using a data, generated during execution of the rounds 1 - 5.1 of the DKG protocol.
    *
    * @param cs cryptosystem, which should be used for a shared public key calculation
    * @param membersPubKeys public keys of all members, who participated in DKG protocol
    * @param memberIdentifier generator of members identifiers, based on the list of members public keys (membersPubKeys)
    * @param roundsData data of all protocol members for the rounds 1 - 5.1
    * @return Success(SharedPublicKey), where the SharedPublicKey is an encoded to a byte representation shared public key - in case of success;
    *         Failure(e) - if an error during computations has occurred.
    */
  def getSharedPublicKey (cs:                       Cryptosystem,
                          membersPubKeys:           Seq[PubKey],
                          memberIdentifier:         Identifier[Int],
                          roundsData:               RoundsData): Try[SharedPublicKey] = Try {

    val allMembersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)

    val absenteesR1 = allMembersIDs.diff(roundsData.r1Data.map(_.issuerID))
    val r2Data = roundsData.r2Data.filter(r2 => !absenteesR1.contains(r2.issuerID)) // cut off possible data from R1 absentees
    val violatorsR1 =
      r2Data.foldLeft(Set[Integer]()){
        (acc, r2) => acc ++ r2.complaints.foldLeft(Set[Integer]()){
            (acc, c) => acc + c.violatorID
        }
      }
    val disqualifiedMembersOnR1 = absenteesR1 ++ violatorsR1

    val r3Data = roundsData.r3Data.filter(r3 =>
      !disqualifiedMembersOnR1.contains(r3.issuerID))
    val absenteesR3 =
      allMembersIDs.diff(disqualifiedMembersOnR1).diff(r3Data.map(_.issuerID))

    val r4Data = roundsData.r4Data.filter(r4 =>
      !disqualifiedMembersOnR1.contains(r4.issuerID) &&
      !absenteesR3.contains(r4.issuerID)) // cut off possible data from R1 disqualified members and R3 absentees
    val violatorsR3 =
      r4Data.foldLeft(Set[Integer]()){
        (acc, r4) => acc ++ r4.complaints.foldLeft(Set[Integer]()){
          (acc, c) => acc + c.violatorID
        }
      }
    val disqualifiedMembersOnR3 = absenteesR3 ++ violatorsR3

    val validCommitments =
      r3Data.filter(r3 => !disqualifiedMembersOnR3.contains(r3.issuerID)).
        map(r3 => Commitment(r3.issuerID, r3.commitments.map(cs.decodePoint)))


    val r5_1Data = roundsData.r5_1Data.filter(
      r5 =>
        !disqualifiedMembersOnR1.contains(r5.issuerID) &&
        !disqualifiedMembersOnR3.contains(r5.issuerID)
    )

    val disqualifiedR3MembersShares = new ArrayBuffer[ViolatorShare]

    // Retrieving shares of each disqualified at round 3 member
    r5_1Data.foreach {
      _.violatorsShares.foreach{
        share =>
          val (violatorID, violatorShare) = share

          disqualifiedR3MembersShares.find(_.violatorID == violatorID) match {
            case Some(vs) => vs.violatorShares += violatorShare
            case _ => disqualifiedR3MembersShares += ViolatorShare(violatorID, new ArrayBuffer[OpenedShare] += violatorShare)
          }
       }
    }

    val t = (membersPubKeys.size.toFloat / 2).ceil.toInt

    val violatorsSecretKeys = disqualifiedR3MembersShares.map(
      share =>
        SecretKey(share.violatorID, LagrangeInterpolation.restoreSecret(cs, share.violatorShares, t).toByteArray)
    )

    val violatorsPublicKeys = violatorsSecretKeys.map(
      sk =>
        cs.basePoint.multiply(new BigInteger(sk.secretKey))
    )

    val honestPublicKeysSum = validCommitments.foldLeft(cs.infinityPoint){
      (acc, c) => acc.add(c.commitment.head)
    }

    val violatorsPublicKeysSum = violatorsPublicKeys.foldLeft(cs.infinityPoint){
      (acc, pubKey) => acc.add(pubKey)
    }

    val sharedPublicKey = honestPublicKeysSum.add(violatorsPublicKeysSum)
    sharedPublicKey.getEncoded(true)
  }

  def checkR1Data(r1Data:           R1Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey]): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r1Data.issuerID), "Illegal issuer's ID")

    val membersNum = membersPubKeys.length
    require(r1Data.E.length   <= membersNum, "Exceeding number of CRS commitments")
    require(r1Data.S_a.length <= membersNum, "Exceeding number of S_a secret shares")
    require(r1Data.S_b.length <= membersNum, "Exceeding number of S_b secret shares")

    // CRS commitment validity can verify only a member of DKG protocol, as a private key for secret shares decryption is needed
  }

  def checkR2Data(r2Data:           R2Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey],
                  cs:               Cryptosystem): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r2Data.issuerID), "Illegal issuer's ID")

    val membersNum = membersPubKeys.length
    require(r2Data.complaints.length <= membersNum, "Exceeding number of R2 complaints")

    r2Data.complaints.foreach {
      c =>
        require(membersIDs.contains(c.violatorID), "Illegal violator's ID")
        require(membersPubKeys.contains(c.issuerPublicKey), "Illegal issuer's public key")
        require(checkComplaintR2(cs, c), "Illegal complaint R2")
    }
  }

  def checkR3Data(r3Data:           R3Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey]): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r3Data.issuerID), "Illegal issuer's ID")

    val membersNum = membersPubKeys.length
    require(r3Data.commitments.length <= membersNum, "Exceeding number of commitments")

    // Commitment validity can verify only a member of DKG protocol, as a set of decrypted on his private key shares is needed
  }

  def checkR4Data(r4Data:           R4Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey],
                  cs:               Cryptosystem,
                  h:                Point,
                  r1DataSeq:        Seq[R1Data],
                  r3DataSeq:        Seq[R3Data]): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r4Data.issuerID), "Illegal issuer's ID")

    val membersNum = membersPubKeys.length
    require(r4Data.complaints.length <= membersNum, "Exceeding number of R4 complaints")

    def checkComplaintR4(complaint: ComplaintR4): Boolean = {

      val r1DataOpt = r1DataSeq.find(_.issuerID == complaint.violatorID)
      require(r1DataOpt.isDefined, s"R1 commitments are absent for ${complaint.violatorID}")

      val r3DataOpt = r3DataSeq.find(_.issuerID == complaint.violatorID)
      require(r3DataOpt.isDefined, s"R3 commitments are absent for ${complaint.violatorID}")

      val CRS_Ok = checkOnCRS(cs, h, complaint.share_a, complaint.share_b, r1DataOpt.get.E)

      val share = Share(r1DataOpt.get.issuerID, complaint.share_a, complaint.share_b)
      val Commitment_Ok = checkCommitmentR3(cs, share, r3DataOpt.get.commitments)

      CRS_Ok && !Commitment_Ok
    }

    r4Data.complaints.foreach {
      c =>
        require(membersIDs.contains(c.violatorID), "Illegal violator's ID")
        require(c.share_a.receiverID == r4Data.issuerID, s"Share_a doesn't belong to the issuer ${r4Data.issuerID} (share_a receiver ID is ${c.share_a.receiverID})")
        require(c.share_b.receiverID == r4Data.issuerID, s"Share_a doesn't belong to the issuer ${r4Data.issuerID} (share_b receiver ID is ${c.share_b.receiverID})")
        require(checkComplaintR4(c), s"Illegal complaint on ${c.violatorID} from ${r4Data.issuerID}")
    }
  }

  def checkR5Data(r5_1Data:         R5_1Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey],
                  cs:               Cryptosystem,
                  r1DataSeq:        Seq[R1Data]): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r5_1Data.issuerID), "Illegal issuer's ID")

    val membersNum = membersPubKeys.length
    require(r5_1Data.violatorsShares.length <= membersNum, "Exceeding number of R5_1 opened shares")

    def checkOpenedShare(shareIssuerID: Integer, share: OpenedShare): Boolean = {

      val r1DataOpt = r1DataSeq.find(_.issuerID == shareIssuerID)
      require(r1DataOpt.isDefined, s"Missing secret shares of $shareIssuerID")

      val secretShareOpt = r1DataOpt.get.S_a.find(_.receiverID == share.receiverID)
      require(secretShareOpt.isDefined, s"Secret share for ${share.receiverID} is missing among secret shares of $shareIssuerID")

      val shareCiphertext = cs.hybridEncrypt(
        cs.infinityPoint,                     // for this verification no matter what public key is used
        share.S.decryptedMessage,
        Array.fill(32)(1.toByte),             // for this verification no matter what secret seed is used
        Some(share.S.decryptedKey)
      )

      // Check if an encrypted opened share is the same as previously submitted secret share
      secretShareOpt.get.S.encryptedMessage.sameElements(
        shareCiphertext.encryptedMessage
      )
    }

    r5_1Data.violatorsShares.foreach {
      s =>
        require(membersIDs.contains(s._1), "Illegal violator's ID")
        require(s._2.receiverID == r5_1Data.issuerID, s"Share doesn't belong to the issuer ${r5_1Data.issuerID} (share receiver ID is ${s._2.receiverID})")
        require(checkOpenedShare(s._1, s._2))
    }
  }
}