package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.protocol.keygen_2_0.datastructures.{HoldersOutput, OutputDKG, OutputMaintenance, ProactiveShare, SecretShare, Share}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RncePublicKeyLight
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

  val partialSecretsInitial: ArrayBuffer[(BigInt, BigInt)] = ArrayBuffer[(BigInt, BigInt)]()
  val combinedShares1: ArrayBuffer[Share] = ArrayBuffer[Share]() // set of combined shares1 for each owned HolderId
  val combinedShares2: ArrayBuffer[Share] = ArrayBuffer[Share]() // set of combined shares2 for each owned HolderId

  private def randZq = context.group.createRandomNumber

  def generate(nominationsNext: Seq[Nomination]): Seq[HoldersOutput] = {

    val ephemeralPubKeysNext = nominationsNext.map(_.ephemeralPubKey)
    val holdingCommittee = SharingParameters(ephemeralPubKeysNext)

    ephemeralOwnKeyPairs.map{ // creating and sharing partial secrets according to a Holder-roles number for a current Node
      _ =>
        val (sk1, sk2) = (randZq, randZq)
        partialSecretsInitial += Tuple2(sk1, sk2)

        val sk1_shares = Holder.shareSecret(context, IdPointMap.emptyPoint, sk1, holdingCommittee)
        val sk2_shares = Holder.shareSecret(context, IdPointMap.emptyPoint, sk2, holdingCommittee)

        OutputDKG(
          sk1_shares = Holder.encryptShares(context, rnceParams, sk1_shares, holdingCommittee.keyToIdMap),
          sk2_shares = Holder.encryptShares(context, rnceParams, sk2_shares, holdingCommittee.keyToIdMap),
          pubKeyPartial = RncePublicKeyLight.create(sk1, sk2, rnceParams.crs)(context.group)
        )
    }.map(outputDkg => HoldersOutput(Some(outputDkg), None))
  }

  def reshare(allHoldersOuptuts: Seq[HoldersOutput],
              nominationsNext:   Seq[Nomination]): Seq[HoldersOutput] = {

    val ephemeralPubKeysNext = nominationsNext.map(_.ephemeralPubKey)

    val sharingCommittee = SharingParameters(ephemeralPubKeys)
    val holdingCommittee = SharingParameters(ephemeralPubKeysNext)

    val allShares_1_2 = allHoldersOuptuts.map{ output =>
      require(output.dkg.isDefined || output.maintenance.isDefined, "Dkg or Maintenance part should be defined")
      if(output.dkg.isDefined) { (output.dkg.get.sk1_shares, output.dkg.get.sk2_shares) }
      else { (output.maintenance.get.s1_shares, output.maintenance.get.s2_shares)}
    }

    // Shares posted by all previous epoch Holders
    val allShares1 = allShares_1_2.flatMap(_._1) // shares of the first secret sk1
    val allShares2 = allShares_1_2.flatMap(_._2) // shares of the second secret sk2

    ephemeralOwnKeyPairs.map{
      ownKeyPair =>

        combinedShares1 += Holder.combineOwnShares(context, rnceParams, ownKeyPair, allShares1, sharingCommittee).get
        combinedShares2 += Holder.combineOwnShares(context, rnceParams, ownKeyPair, allShares2, sharingCommittee).get

        val ownId = memberIdentifier.getId(ownKeyPair._2).get
        val ownPoint = IdPointMap.toPoint(ownId)
        require(ownPoint == combinedShares1.last.point && ownPoint == combinedShares2.last.point, "Own point is inconsistent with combined shares points")

        val s1_shares = Holder.shareSecret(context, IdPointMap.toPoint(ownId), combinedShares1.last.value, holdingCommittee)
        val s2_shares = Holder.shareSecret(context, IdPointMap.toPoint(ownId), combinedShares2.last.value, holdingCommittee)

        OutputMaintenance(
          Holder.encryptShares(context, rnceParams, s1_shares, holdingCommittee.keyToIdMap),
          Holder.encryptShares(context, rnceParams, s2_shares, holdingCommittee.keyToIdMap)
        )
    }.map(outputMaintenance => HoldersOutput(None, Some(outputMaintenance)))
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

  // Extracts own shares, i.e. the shares encrypted on public key of the current Holder
  // Sums up all own shares
  // Multiplies each share on the corresponding Dealer's lambda if shared secret is a combined share from previous epoch
  def combineOwnShares(context:         CryptoContext,
                       rnceParams:      RnceParams,
                       keyPair:         RnceKeyPair,
                       allShares:       Seq[SecretShare],
                       committeeParams: SharingParameters): Try[Share] = Try {

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
    Share(IdPointMap.toPoint(ownId), ownSharesSum)
  }
}
