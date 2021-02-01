package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.protocol.keygen_2_0.datastructures.SecretShare
import io.iohk.protocol.keygen_2_0.datastructures.{ProactiveShare, ProactiveShareSerializer, Share}
import io.iohk.protocol.keygen_2_0.dlog_encryption.DLogEncryption
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import io.iohk.protocol.keygen_2_0.math.{LagrangeInterpolation, Polynomial}

import scala.collection.mutable.ArrayBuffer
import scala.util.{Random, Success, Try}

case class SharingParameters(pubKeys: Seq[PubKey]){
  val n: Int = pubKeys.size
  val t: Int = n / 2 + 1
  val keyToIdMap = new CommitteeIdentifier(pubKeys)
  val allIds: Seq[Int] = pubKeys.flatMap(keyToIdMap.getId)
}

object IdPointMap{
  val emptyPoint: Int = -1
  def toPoint(id: Int): Int = { id + 1 }
  def toId(point: Int): Int = { point - 1 }
}

case class Holder(context              : CryptoContext,
                  ephemeralOwnKeyPairs : Seq[KeyPair],
                  ephemeralPubKeys     : Seq[PubKey]) {

  private val n = ephemeralPubKeys.size
  private val t = n / 2 + 1
  private val memberIdentifier = new CommitteeIdentifier(ephemeralPubKeys)
  private val membersIds = ephemeralPubKeys.flatMap(memberIdentifier.getId)

  val partialSecretsInitial: ArrayBuffer[BigInt] = ArrayBuffer[BigInt]()
  val combinedShares: ArrayBuffer[(Int, BigInt)] = ArrayBuffer[(Int, BigInt)]() // set of combined shares for each owned Id (i.e. point)

  def generate(nominationsNext: Seq[Nomination]): Seq[SecretShare] = {

    val ephemeralPubKeysNext = nominationsNext.map(_.ephemeralPubKey)
    val holdingCommittee = SharingParameters(ephemeralPubKeysNext)

    ephemeralOwnKeyPairs.flatMap{
      _ =>
        partialSecretsInitial += BigInt(Random.nextInt())
        val shares = Holder.shareSecret(context, IdPointMap.emptyPoint, partialSecretsInitial.last, holdingCommittee)
        Holder.encryptShares(context, shares, holdingCommittee.keyToIdMap)
    }
  }

  def reshare(allShares: Seq[SecretShare],
              nominationsNext: Seq[Nomination]): Seq[SecretShare] = {

    val ephemeralPubKeysNext = nominationsNext.map(_.ephemeralPubKey)

    val sharingCommittee = SharingParameters(ephemeralPubKeys)
    val holdingCommittee = SharingParameters(ephemeralPubKeysNext)

    ephemeralOwnKeyPairs.flatMap{
      ownKeyPair =>
        val ownId = memberIdentifier.getId(ownKeyPair._2).get
        combinedShares += Holder.combineOwnShares(context, ownKeyPair, allShares, sharingCommittee).get
        val newShares = Holder.shareSecret(context, IdPointMap.toPoint(ownId), combinedShares.last._2, holdingCommittee)
        Holder.encryptShares(context, newShares, holdingCommittee.keyToIdMap)
    }
  }
}

object Holder
{
  def create(context     : CryptoContext,
             ownKeyPair  : KeyPair, // own long-term key pair
             nominations : Seq[Nomination]): Option[Holder] = {
    import context.{group, blockCipher}

    val ownLongTermPrivKey = ownKeyPair._1
    val ownEphemeralKeyPairs =
      nominations.flatMap{
        n =>
          HybridEncryption.decrypt(ownLongTermPrivKey, n.ephemeralPrivKeyEnc) match {
            case Success(ephemeralPrivKeyPlain) => Option(Tuple2(BigInt(ephemeralPrivKeyPlain.decryptedMessage), n.ephemeralPubKey))
            case _ => None // means that "mac check in GCM failed" in "doFinal" of the "AES/GCM/NoPadding"
          }
      }

    if(ownEphemeralKeyPairs.nonEmpty){
      Option(Holder(context, ownEphemeralKeyPairs, nominations.map(_.ephemeralPubKey)))
    } else {
      None
    }
  }

  private def getShares(poly: Polynomial, evaluationPoints: Seq[Int]) : Seq[Share] = {
    evaluationPoints.map{
      point =>
        assert(point != 0) // avoid disclosing a_0 coefficient
        Share(point, poly.evaluate(point))
    }
  }

  def shareSecret(context: CryptoContext,
                  dealerPoint: Int,
                  secret: BigInt,
                  holdingCommittee: SharingParameters): Seq[ProactiveShare] = {

    val F = Polynomial(context.group, holdingCommittee.t - 1, secret)
    val evaluation_points_F = holdingCommittee.allIds.map(IdPointMap.toPoint)
    val shares = getShares(F, evaluation_points_F)
    shares.map(ProactiveShare(dealerPoint, _))
  }

  def reconstructSecret(context: CryptoContext,
                        all_shares: Seq[ProactiveShare]): BigInt = {
    LagrangeInterpolation.restoreSecret(context.group, all_shares.map(_.f_share))
  }

  def encryptShares(context: CryptoContext,
                    shares: Seq[ProactiveShare],
                    keyToIdMap: CommitteeIdentifier): Seq[SecretShare] = {
    import context.group

    shares.map{
      share =>
        val receiverId = IdPointMap.toId(share.f_share.point)
        val receiverPubKey = keyToIdMap.getPubKey(receiverId).get
        SecretShare(
          receiverId,
          share.dealerPoint,
          DLogEncryption.encrypt(share.f_share.value, receiverPubKey).get._1
        )
    }
  }

  def decryptShares(context: CryptoContext,
                    secretShares: Seq[SecretShare],
                    privKey: PrivKey): Try[Seq[ProactiveShare]] = Try {
    import context.group

    secretShares.map{
      secretShare =>
        val share = DLogEncryption.decrypt(secretShare.S, privKey).get
        val point = IdPointMap.toPoint(secretShare.receiverID)
        ProactiveShare(secretShare.dealerPoint, Share(point, share))
    }
  }

  def combineOwnShares(context: CryptoContext,
                       keyPair: KeyPair,
                       allShares: Seq[SecretShare],
                       committeeParams: SharingParameters): Try[(Int, BigInt)] = Try {

    val modulus = context.group.groupOrder
    val (privKey, pubKey) = keyPair

    val ownId = committeeParams.keyToIdMap.getId(pubKey).get
    val ownSecretShares = allShares.filter(_.receiverID == ownId)

    val ownShares = decryptShares(context, ownSecretShares, privKey).get

    // Getting all points of Mf's dealers
    // Note: lambda value for Mf can be computed only when a set of all published Mf's is known
    val all_dealers_points = ownShares.map(_.dealerPoint).distinct

    val ownSharesSum =
      ownShares.foldLeft(BigInt(0)){
        (sum, share) =>
          val lambda  = { // lambda that corresponds to Mf of the current dealer (the dealer who generated the current share of its own Mf)
            if(all_dealers_points.size == 1 && all_dealers_points.head == IdPointMap.emptyPoint){
              BigInt(1)
            } else {
              LagrangeInterpolation.getLagrangeCoeff(context.group, share.dealerPoint, all_dealers_points)
            }
          }
          (sum + lambda * share.f_share.value).mod(modulus)
    }
    (IdPointMap.toPoint(ownId), ownSharesSum)
  }
}
