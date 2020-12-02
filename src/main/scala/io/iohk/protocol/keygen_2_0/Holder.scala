package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.protocol.keygen_2_0.datastructures.SecretShare
import io.iohk.protocol.keygen_2_0.datastructures.{ProactiveShare, ProactiveShareSerializer, Share}
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

  val partialSecretsInitial = ArrayBuffer[BigInt]()
  val ownSharesSum = ArrayBuffer[(Int, BigInt)]() // set of summed shares for points those correspond to an each owned Id

//  import context.{group, blockCipher}

  def generate(nominationsNext: Seq[Nomination]): Seq[SecretShare] = {

    val ephemeralPubKeysNext = nominationsNext.map(_.ephemeralPubKey)

    val sharingCommittee = SharingParameters(ephemeralPubKeys)
    val holdingCommittee = SharingParameters(ephemeralPubKeysNext)

    ephemeralOwnKeyPairs.flatMap{
      ownKeyPair =>
        partialSecretsInitial += BigInt(Random.nextInt())
        val shares = Holder.shareSecret(context, IdPointMap.emptyPoint, partialSecretsInitial.last, sharingCommittee, holdingCommittee).flatten
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
        ownSharesSum += Holder.sumOwnShares(context, ownKeyPair, allShares, sharingCommittee).get
        val newShares = Holder.shareSecret(context, IdPointMap.toPoint(ownId), ownSharesSum.last._2, sharingCommittee, holdingCommittee).flatten
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
            case _ => None // "mac check in GCM failed" in "doFinal" of the "AES/GCM/NoPadding"
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
        assert(point != 0) // avoid share for a_0 coefficient
        Share(point, poly.evaluate(point))
    }
  }

  def shareSecret(context: CryptoContext,
                  dealerPoint: Int,
                  secret: BigInt,
                  sharingCommittee: SharingParameters,
                  holdingCommittee: SharingParameters): Seq[Seq[ProactiveShare]] = {

    val F = Polynomial(context.group, sharingCommittee.t - 1, secret)
    val evaluation_points_F = sharingCommittee.allIds.map(IdPointMap.toPoint)
    val shares = getShares(F, evaluation_points_F)

    val evaluation_points_G = holdingCommittee.allIds.map(IdPointMap.toPoint)
    val shared_shares = // share_j -> G_j(1), G_j(2),... G_j(n_next); j = [1, n]
      shares.map{
        share_j =>
          val G = Polynomial(context.group, holdingCommittee.t - 1, share_j.value)
          val G_shares = getShares(G, evaluation_points_G)
          G_shares.map(ProactiveShare(dealerPoint, share_j.point, _))
      }
    shared_shares.transpose // arrange shares correspondingly to receivers
  }

  def reconstructSecret(context: CryptoContext,
                        all_shares: Seq[ProactiveShare],
                        sharingCommittee: SharingParameters,
                        holdingCommittee: SharingParameters): Try[BigInt] = Try {
    val modulus = context.group.groupOrder

    val all_points_F = all_shares.map(_.f_point).distinct
    val g_shares_by_Fj = { // share_j -> G_j(1), G_j(2),... G_j(n_next); j = [1, n]
      all_points_F.flatMap{
        f_point =>
          val g_shares = all_shares.filter(_.f_point == f_point)
          g_shares.size match {
            case size if size >= holdingCommittee.t => Some(g_shares.take(holdingCommittee.t))
            case _ => None
          }
      }
    }

    assert(g_shares_by_Fj.size >= sharingCommittee.t)

    val shares_of_F = g_shares_by_Fj.take(sharingCommittee.t).map{
      g_shares =>
        assert(g_shares.forall(_.f_point == g_shares.head.f_point)) // all shares are for the same Fj share
        val shares = g_shares.map(_.g_share)
        Share(g_shares.head.f_point, LagrangeInterpolation.restoreSecret(context.group, shares))
    }

    LagrangeInterpolation.restoreSecret(context.group, shares_of_F)
  }

  def encryptShares(context: CryptoContext,
                    shares: Seq[ProactiveShare],
                    keyToIdMap: CommitteeIdentifier): Seq[SecretShare] = {
    import context.{group, blockCipher}

    shares.map{
      share =>
        val receiverId = IdPointMap.toId(share.g_share.point)
        val receiverPubKey = keyToIdMap.getPubKey(receiverId).get
        SecretShare(
          receiverId,
          HybridEncryption.encrypt(receiverPubKey, share.bytes).get
        )
    }
  }

  def decryptShares(context: CryptoContext,
                    secretShares: Seq[SecretShare],
                    privKey: PrivKey): Try[Seq[ProactiveShare]] = Try {
    import context.{group, blockCipher}

    secretShares.map{
      secretShare =>
        ProactiveShareSerializer.parseBytes(HybridEncryption.decrypt(privKey, secretShare.S).get.decryptedMessage).get
    }
  }

  def sumOwnShares(context: CryptoContext,
                   keyPair: KeyPair,
                   allShares: Seq[SecretShare],
                   committeeParams: SharingParameters): Try[(Int, BigInt)] = Try {

    val modulus = context.group.groupOrder
    val (privKey, pubKey) = keyPair

    val ownId = committeeParams.keyToIdMap.getId(pubKey).get
    val ownSecretShares = allShares.filter(_.receiverID == ownId)

    val ownShares = decryptShares(context, ownSecretShares, privKey).get
    val all_points_F = ownShares.map(_.f_point).distinct
//    assert(all_points_F.size == prev_n) // each party should get G-shares for each F-share

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
          // Getting a Lagrange coefficient that corresponds to an F-share to which current G-share belongs
          val lambdaF = LagrangeInterpolation.getLagrangeCoeff(context.group, share.f_point, all_points_F)
          (sum + lambda * lambdaF * share.g_share.value).mod(modulus)
    }

//    // Computing lambda * Mf only for a case of "n of n" participation of committee members in the Mfs publishing
//    val evaluation_points = committeeParams.allIds.map(IdPointMap.toPoint)
//    val lambda = LagrangeInterpolation.getLagrangeCoeff(context, IdPointMap.toPoint(ownId), evaluation_points)
//    (ownId, (lambda * ownSharesSum).mod(modulus))

    (IdPointMap.toPoint(ownId), ownSharesSum)
  }
}
