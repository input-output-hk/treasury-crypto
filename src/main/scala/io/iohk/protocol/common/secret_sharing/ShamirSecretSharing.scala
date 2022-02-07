package io.iohk.protocol.common.secret_sharing

import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import io.iohk.protocol.common.datastructures.{SecretShare, Share}
import io.iohk.protocol.common.dlog_encryption.{DLogEncryption, DLogRandomness}
import io.iohk.protocol.common.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.evaluateLiftedPoly

import scala.util.Try

object ShamirSecretSharing {

  // pubKeys - public keys of all parties who will receive the shares of a secret
  case class SharingParameters(pubKeys: Seq[PubKey]){
    val n: Int = pubKeys.size // total number of parties
    val t: Int = n / 2 + 1    // sharing threshold (minimum number of shares needed to reconstruct a secret)
    val keyToIdMap = new CommitteeIdentifier(pubKeys)
    val allIds: Seq[Int] = pubKeys.flatMap(keyToIdMap.getId)
  }

  object IdPointMap{
    val emptyPoint: Int = -1
    def toPoint(id: Int): Int = { id + 1 }
    def toId(point: Int): Int = { point - 1 }
  }

  def getShares(poly: Polynomial, evaluationPoints: Seq[Int]) : Seq[Share] = {
    evaluationPoints.map{
      point =>
        assert(point != 0) // avoid disclosing the a_0 coefficient (contains a shared secret)
        Share(point, poly.evaluate(point))
    }
  }

  def reconstructSecret(context: CryptoContext,
                        all_shares: Seq[Share]): BigInt = {
    LagrangeInterpolation.restoreSecret(context.group, all_shares)
  }

  def encryptShares(context: CryptoContext,
                    shares: Seq[Share],
                    params: SharingParameters): Seq[(SecretShare, DLogRandomness)] = {
    import context.group

    shares.map{
      share =>
        val receiverId = IdPointMap.toId(share.point)
        val receiverPubKey = params.keyToIdMap.getPubKey(receiverId).get
        val encShare = DLogEncryption.encrypt(share.value, receiverPubKey).get
        (
          SecretShare(
            receiverId,
            encShare._1,
//            Some(share.value) // TODO: comment this line for real use
          ),encShare._2
        )
    }
  }

  def decryptShares(context: CryptoContext,
                    secretShares: Seq[SecretShare],
                    privKey: PrivKey): Try[Seq[Share]] = Try {
    import context.group

    secretShares.map{
      secretShare =>
        val share = secretShare.plainS match {
          case None => DLogEncryption.decrypt(secretShare.S, privKey).get
          case Some(plainS) => plainS
        }
        val point = IdPointMap.toPoint(secretShare.receiverID)
        Share(point, share)
    }
  }

  def shareIsValid(context: CryptoContext,
                   sharingThreshold: Int, // here defines the number of committed polynomial coefficients needed for share validation
                   share: Share,          // share to be validated
                   dealersCoeffsCommitments: Seq[GroupElement] // coefficients commitments of the polynomial used to create the share
                  ): Boolean = {
    import context.group
    dealersCoeffsCommitments.length == sharingThreshold &&
      (evaluateLiftedPoly(dealersCoeffsCommitments, share.point)
        == group.groupGenerator.pow(share.value).get)
  }
}
