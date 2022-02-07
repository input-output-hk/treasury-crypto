package io.iohk.protocol.resharing

import io.iohk.core.crypto.encryption.{KeyPair, PubKey}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.datastructures.Share
import io.iohk.protocol.common.dlog_encryption.NIZKs.CorrectDecryptionNIZK.CorrectDecryption
import io.iohk.protocol.common.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.exp
import io.iohk.protocol.common.secret_sharing.ShamirSecretSharing.{IdPointMap, SharingParameters, decryptShares, encryptShares, getShares, shareIsValid}
import io.iohk.protocol.resharing.datastructures.{Complaint, DealersShare, IndexedComplaint, ResharingComplaints, ResharingData, SharedShare}

import scala.collection.mutable.ArrayBuffer

case class Resharing(context:    CryptoContext,
                     ownKeyPair: KeyPair,
                     allPubKeys: Seq[PubKey]) // keys of the resharings receivers
{
  assert(allPubKeys.contains(ownKeyPair._2))  // own key-pair should be among the participating parties keys

  private val params = SharingParameters(allPubKeys)
  private val (ownPrivKey, ownPubKey) = ownKeyPair
  private val ownID = params.keyToIdMap.getId(ownPubKey).get

  import context.group

  case class ReceivedShare(dealerId: Int, share: BigInt, sharedValueIndex: Int)

  private val resharingsData = ArrayBuffer[ResharingData]()
  private val receivedShares = ArrayBuffer[ReceivedShare]()

  def receiveResharings(resharingsDataIn: Seq[ResharingData]): Option[ResharingComplaints] = {
    assert(resharingsData.isEmpty && receivedShares.isEmpty)
    resharingsData ++= resharingsDataIn

    // Checking that all R1Data-messages are from different parties
    assert(resharingsData.map(_.senderID).distinct.length == resharingsData.length)

    val complaints = resharingsData.flatMap{
      d => // validating the shares received from each dealer
        // Checking that each resharing contains a share for ownId
        assert(d.sharedShares.forall(_.encShares.exists(_.receiverID == ownID)))
        // Extracting and decrypting the shares received from a current dealer
        val encShares = d.sharedShares.flatMap(_.encShares.filter(_.receiverID == ownID))
        val openedShares = decryptShares(context, encShares, ownPrivKey)
        assert(openedShares.isSuccess)

        // Validating each opened share and creating complaint if the share is not valid
        openedShares.get
          .zip(encShares) // Seq[(openedShare, encryptedShare)]
          .zip(d.sharedShares.map(_.coeffsCommitments))
          .zipWithIndex
          .flatMap{
            // Checking an own share from each resharing
            case(((share, encShare), coeffsCommitments), i) =>
              if (!shareIsValid(context, params.t, share, coeffsCommitments)){
                // Creating complaint on the current resharing of the current dealer
                val st = CorrectDecryption.Statement(ownPubKey, share.value, encShare.S)
                val w = CorrectDecryption.Witness(ownPrivKey)
                Some(
                  IndexedComplaint(
                    Complaint(DealersShare(d.senderID, share.value), CorrectDecryption(st).prove(w)),
                    i
                  )
                )
              } else {
                receivedShares += ReceivedShare(d.senderID, share.value, i)
                None
              }
          }
    }

    if(complaints.nonEmpty){
      Some(ResharingComplaints(ownID, complaints))
    } else {
      None
    }
  }

  def buildNewShares(complaintsData: Seq[ResharingComplaints]): Seq[Share] = {
    assert(resharingsData.nonEmpty && receivedShares.nonEmpty)

    // Use only the ResharingComplaints which contain all valid complaints
    val validComplaintsData = complaintsData.filter{d =>
      d.complaints.forall(complaintIsValid(d.senderID, _))
    }

    val disqualifiedDealers = validComplaintsData.flatMap(_.complaints.map(_.complaint.share.dealerID)).distinct
    val qualShares = receivedShares.filter(s => !disqualifiedDealers.contains(s.dealerId))

    val allDealersPoints = qualShares.map(s => IdPointMap.toPoint(s.dealerId)).distinct
    val sharesByIndex = receivedShares.groupBy(s => s.sharedValueIndex)
    // The same number of shared shares for all reshared values
    assert(sharesByIndex.forall(_._2.length == sharesByIndex.head._2.length))
    // The number of shared shares of each reshared value is the same as number of dealers
    assert(sharesByIndex.head._2.length == allDealersPoints.length)

    sharesByIndex.map{
      case (i, shares) =>
        (
          i,
          shares.foldLeft(BigInt(0)) {
            (sum, shareEntry) =>
              // lambda that corresponds to Mf of the current dealer (the dealer who generated the current share of its own Mf)
              val lambda = LagrangeInterpolation.getLagrangeCoeff(group, IdPointMap.toPoint(shareEntry.dealerId), allDealersPoints)
              (sum + lambda * shareEntry.share).mod(group.groupOrder)
          }
        )
    }.toSeq
      .sortBy(_._1)
      .map(i_share => Share(IdPointMap.toPoint(ownID), i_share._2)) // new shares arranged by index
  }

  def complaintIsValid(complaintSenderId: Int,
                       complaintIndexed: IndexedComplaint): Boolean = {
    val (complaint, invalidShareIndex) = (complaintIndexed.complaint, complaintIndexed.index)
    val pk = params.keyToIdMap.getPubKey(complaintSenderId).get

    val invalidResharing = resharingsData
      .find(_.senderID == complaint.share.dealerID).get // set of resharings distributed by a specific dealer
      .sharedShares(invalidShareIndex) // the resharing containing the invalid share (by the specified position)

    val encShare = invalidResharing
      .encShares.find(_.receiverID == complaintSenderId).get // encrypted share of the complaining party at specified position

    val st = CorrectDecryption.Statement(pk, complaint.share.openedShare, encShare.S)

    !shareIsValid(context, params.t, Share(IdPointMap.toPoint(complaintSenderId), complaint.share.openedShare), invalidResharing.coeffsCommitments) &&
      CorrectDecryption(st).verify(complaint.proof)
  }
}

object Resharing {

  // Reshares the shared secret by sharing each of it's shares
  // Shares (without evaluation point - it is the same, corresponding to the ownId) to be reshared
  def getResharings(context:  CryptoContext,
                    params:   SharingParameters,  // contains the keys of resharings receivers
                    dealerID: Int,                // ID of the resharing party
                    shares:   Seq[BigInt]         // shares of the secret to be reshared
                   ): ResharingData = {
    ResharingData(dealerID, shares.map(reshare(context, params, _)))
  }

  def reshare(context:  CryptoContext,
              params:   SharingParameters,
              share:    BigInt): SharedShare = {

    import context.group
    val g = group.groupGenerator

    val polynomial = Polynomial(context.group, params.t - 1, share)
    // Resharing the 'share' with the new polynomial
    val shares = getShares(polynomial, params.allIds.map(IdPointMap.toPoint))
    // Encrypting the shares of the 'share'
    val encShares = encryptShares(context, shares, params).map(_._1)
    val coeffsCommitments = polynomial.coeffs().map(exp(g, _)) // g^coeff

    SharedShare(encShares, coeffsCommitments)
  }
}
