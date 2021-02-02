package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.protocol.keygen_2_0.datastructures.SecretShare
import io.iohk.protocol.keygen_2_0.datastructures.{ProactiveShare, Share}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.keygen_2_0.rnce_encryption.{RnceKeyPair, RncePrivKey, RncePubKey}
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.RnceBatchedSecretKeySerializer
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}

import scala.collection.mutable.ArrayBuffer
import scala.util.{Random, Success, Try}

case class SharingParameters(pubKeys: Seq[RncePubKey]){
  val n: Int = pubKeys.size
  val t: Int = n / 2 + 1
  val keyToIdMap = new CommitteeIdentifierRnce(pubKeys)
  val allIds: Seq[Int] = pubKeys.flatMap(keyToIdMap.getId)
}

object IdPointMap{
  val emptyPoint: Int = -1
  def toPoint(id: Int): Int = { id + 1 }
  def toId(point: Int): Int = { point - 1 }
}

case class Holder(context              : CryptoContext,
                  rnceParams           : RnceParams,
                  ephemeralOwnKeyPairs : Seq[RnceKeyPair],
                  ephemeralPubKeys     : Seq[RncePubKey]) {

  private val n = ephemeralPubKeys.size
  private val t = n / 2 + 1
  private val memberIdentifier = new CommitteeIdentifierRnce(ephemeralPubKeys)
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
        Holder.encryptShares(context, rnceParams, shares, holdingCommittee.keyToIdMap)
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
        combinedShares += Holder.combineOwnShares(context, rnceParams, ownKeyPair, allShares, sharingCommittee).get
        val newShares = Holder.shareSecret(context, IdPointMap.toPoint(ownId), combinedShares.last._2, holdingCommittee)
        Holder.encryptShares(context, rnceParams, newShares, holdingCommittee.keyToIdMap)
    }
  }
}

object Holder
{
  def create(context     : CryptoContext,
             rnceParams  : RnceParams,
             ownKeyPair  : KeyPair, // own long-term key pair
             nominations : Seq[Nomination]): Option[Holder] = {
    import context.{group, blockCipher}

    val ownLongTermPrivKey = ownKeyPair._1
    val ownEphemeralKeyPairs =
      nominations.flatMap{
        n =>
          HybridEncryption.decrypt(ownLongTermPrivKey, n.ephemeralPrivKeyEnc) match {
            case Success(ephemeralPrivKeyPlain) =>
              Option((
                  RnceBatchedSecretKeySerializer.parseBytes(ephemeralPrivKeyPlain.decryptedMessage, Some(group)).get,
                  n.ephemeralPubKey
                ))
            case _ => None // means that "mac check in GCM failed" in "doFinal" of the "AES/GCM/NoPadding"
          }
      }

    if(ownEphemeralKeyPairs.nonEmpty){
      Option(Holder(context, rnceParams, ownEphemeralKeyPairs, nominations.map(_.ephemeralPubKey)))
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

  def encryptShares(context:    CryptoContext,
                    rnceParams: RnceParams,
                    shares:     Seq[ProactiveShare],
                    keyToIdMap: CommitteeIdentifierRnce): Seq[SecretShare] = {
    import context.group

    shares.map{
      share =>
        val receiverId = IdPointMap.toId(share.f_share.point)
        val receiverPubKey = keyToIdMap.getRncePubKey(receiverId).get
        SecretShare(
          receiverId,
          share.dealerPoint,
          RnceBatchedEncryption.encrypt(receiverPubKey, share.f_share.value, rnceParams.crs).get._1
        )
    }
  }

  def decryptShares(context:      CryptoContext,
                    rnceParams:   RnceParams,
                    secretShares: Seq[SecretShare],
                    privKey:      RncePrivKey): Try[Seq[ProactiveShare]] = Try {
    import context.group

    secretShares.map{
      secretShare =>
        val share = RnceBatchedEncryption.decrypt(privKey, secretShare.S, rnceParams.crs).get
        val point = IdPointMap.toPoint(secretShare.receiverID)
        ProactiveShare(secretShare.dealerPoint, Share(point, share))
    }
  }

  def combineOwnShares(context:         CryptoContext,
                       rnceParams:      RnceParams,
                       keyPair:         RnceKeyPair,
                       allShares:       Seq[SecretShare],
                       committeeParams: SharingParameters): Try[(Int, BigInt)] = Try {

    val modulus = context.group.groupOrder
    val (privKey, pubKey) = keyPair

    val ownId = committeeParams.keyToIdMap.getId(pubKey).get
    val ownSecretShares = allShares.filter(_.receiverID == ownId)

    val ownShares = decryptShares(context, rnceParams, ownSecretShares, privKey).get

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
