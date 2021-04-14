package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.datastructures.{HoldersOutput, OutputDKG, OutputMaintenance, ProactiveShare, SecretShare, Share}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.Holder.{getSharesDecProof, getSharesEncProof}
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.CorrectSharesDecryption.Witness
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.{CorrectSharesDecryption, CorrectSharesEncryption}
import io.iohk.protocol.keygen_2_0.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RncePublicKeyLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.{RnceKeyPair, RncePrivKey, RncePubKey}
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.{RnceBatchedCiphertext, RnceBatchedRandomness, RnceBatchedSecretKeySerializer}
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}

import scala.collection.mutable.ArrayBuffer
import scala.util.{Success, Try}

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

case class EncryptionProofData(eval_point: Int,
                               pubKey: RncePubKey,
                               share_enc: (RnceBatchedCiphertext, RnceBatchedRandomness))

case class DecryptionProofData(shares_sum: BigInt,
                               shares_enc: Seq[RnceBatchedCiphertext],
                               gammas: Seq[BigInt])

case class Holder(context              : CryptoContext,
                  rnceParams           : RnceParams,
                  proofsCrs            : (CorrectSharesEncryption.CRS, CorrectSharesDecryption.CRS),
                  ephemeralOwnKeyPairs : Seq[RnceKeyPair],
                  ephemeralPubKeys     : Seq[RncePubKey]) {

  private val n = ephemeralPubKeys.size
  private val t = n / 2 + 1
  private val memberIdentifier = new CommitteeIdentifierRnce(ephemeralPubKeys)
  private val membersIds = ephemeralPubKeys.flatMap(memberIdentifier.getId)
  private val correct_shares_enc_crs = proofsCrs._1
  private val correct_shares_dec_crs = proofsCrs._2

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

        val sk1_shares_enc = Holder.encryptShares(context, rnceParams, sk1_shares._1, holdingCommittee.keyToIdMap)
        val sk2_shares_enc = Holder.encryptShares(context, rnceParams, sk2_shares._1, holdingCommittee.keyToIdMap)

        OutputDKG(
          sk1_shares = sk1_shares_enc.map(_._1),
          sk2_shares = sk2_shares_enc.map(_._1),
          pubKeyPartial = RncePublicKeyLight.create(sk1, sk2, rnceParams.crs)(context.group),
          proofEnc = Some(
            getSharesEncProof(
              correct_shares_enc_crs, context.group,
              (sk1_shares._2, sk2_shares._2),  // (F_poly1, F_poly2)
              (sk1_shares_enc.map(_._2), sk2_shares_enc.map(_._2))
            )
          )
//          proofEnc = None
        )
    }.map(outputDkg => HoldersOutput(Some(outputDkg), None))
  }

  def reshare(allHoldersOutputs: Seq[HoldersOutput],
              nominationsNext:   Seq[Nomination]): Seq[HoldersOutput] = {

    val ephemeralPubKeysNext = nominationsNext.map(_.ephemeralPubKey)

    val sharingCommittee = SharingParameters(ephemeralPubKeys)
    val holdingCommittee = SharingParameters(ephemeralPubKeysNext)

    val allShares_1_2 = allHoldersOutputs.map{ output =>
      require(output.dkg.isDefined || output.maintenance.isDefined, "Dkg or Maintenance part should be defined")
      if(output.dkg.isDefined) { (output.dkg.get.sk1_shares, output.dkg.get.sk2_shares) }
      else { (output.maintenance.get.s1_shares, output.maintenance.get.s2_shares) }
    }

    // Shares posted by all previous epoch Holders
    val allShares1 = allShares_1_2.flatMap(_._1) // shares of the first secret sk1
    val allShares2 = allShares_1_2.flatMap(_._2) // shares of the second secret sk2

    ephemeralOwnKeyPairs.map{
      ownKeyPair =>

        val combined_share1 = Holder.combineOwnShares(context, rnceParams, ownKeyPair, allShares1, sharingCommittee).get
        val combined_share2 = Holder.combineOwnShares(context, rnceParams, ownKeyPair, allShares2, sharingCommittee).get

        // Checking that combined share indeed belongs to the current member
        val ownId = memberIdentifier.getId(ownKeyPair._2).get
        val ownPoint = IdPointMap.toPoint(ownId)
        require(ownPoint == combined_share1._1.point && ownPoint == combined_share2._1.point, "Own point is inconsistent with combined shares points")

        combinedShares1 += combined_share1._1
        combinedShares2 += combined_share2._1

        val s1_shares = Holder.shareSecret(context, IdPointMap.toPoint(ownId), combinedShares1.last.value, holdingCommittee)
        val s2_shares = Holder.shareSecret(context, IdPointMap.toPoint(ownId), combinedShares2.last.value, holdingCommittee)

        val s1_shares_enc = Holder.encryptShares(context, rnceParams, s1_shares._1, holdingCommittee.keyToIdMap)
        val s2_shares_enc = Holder.encryptShares(context, rnceParams, s2_shares._1, holdingCommittee.keyToIdMap)

        OutputMaintenance(
          s1_shares = s1_shares_enc.map(_._1),
          s2_shares = s2_shares_enc.map(_._1),
          proofEnc = Some(
            getSharesEncProof(
              correct_shares_enc_crs, context.group,
              (s1_shares._2, s2_shares._2),  // (F_poly1, F_poly2)
              (s1_shares_enc.map(_._2), s2_shares_enc.map(_._2))
            )
          ),
          proofDec = Some(
            getSharesDecProof(
              correct_shares_dec_crs, context.group,
              ownKeyPair,
              (combined_share1._2, combined_share2._2)
            )
          )
//          proofEnc = None,
//          proofDec = None
        )
    }.map(outputMaintenance => HoldersOutput(None, Some(outputMaintenance)))
  }
}

object Holder
{
  def create(context     : CryptoContext,
             rnceParams  : RnceParams,
             proofsCrs   : (CorrectSharesEncryption.CRS, CorrectSharesDecryption.CRS),
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
      Option(Holder(context, rnceParams, proofsCrs, ownEphemeralKeyPairs, nominations.map(_.ephemeralPubKey)))
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
                  holdingCommittee: SharingParameters): (Seq[ProactiveShare], Polynomial) = {

    val F = Polynomial(context.group, holdingCommittee.t - 1, secret)
    val evaluation_points_F = holdingCommittee.allIds.map(IdPointMap.toPoint)
    val shares = getShares(F, evaluation_points_F)
    (shares.map(ProactiveShare(dealerPoint, _)), F) // Polynomial F is needed for Correct Encryption NIZK-proof
  }

  def reconstructSecret(context: CryptoContext,
                        all_shares: Seq[ProactiveShare]): BigInt = {
    LagrangeInterpolation.restoreSecret(context.group, all_shares.map(_.f_share))
  }

  def encryptShares(context:    CryptoContext,
                    rnceParams: RnceParams,
                    shares:     Seq[ProactiveShare],
                    keyToIdMap: CommitteeIdentifierRnce): Seq[(SecretShare, EncryptionProofData)] = {
    import context.group

    shares.map{
      share =>
        val evalPoint = share.f_share.point
        val receiverId = IdPointMap.toId(evalPoint)
        val receiverPubKey = keyToIdMap.getRncePubKey(receiverId).get
        val share_enc = RnceBatchedEncryption.encrypt(receiverPubKey, share.f_share.value, rnceParams.crs).get
        Tuple2(
          SecretShare(receiverId, share.dealerPoint, share_enc._1),
          EncryptionProofData(evalPoint, receiverPubKey, share_enc) // auxiliary data that is needed for Correct Encryption NIZK-proof
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
                       committeeParams: SharingParameters): Try[(Share, DecryptionProofData)] = Try {

    val modulus = context.group.groupOrder
    val (privKey, pubKey) = keyPair

    val ownId = committeeParams.keyToIdMap.getId(pubKey).get
    val ownSecretShares = allShares.filter(_.receiverID == ownId)

    val ownShares = decryptShares(context, rnceParams, ownSecretShares, privKey).get

    // Getting all points of Mf's dealers
    // Note: lambda value for Mf can be computed only when a set of all published Mf's is known
    val all_dealers_points = ownShares.map(_.dealerPoint).distinct

     val lambdas = ownShares.map{
      share =>
       // lambda that corresponds to Mf of the current dealer (the dealer who generated the current share of its own Mf)
      if(all_dealers_points.size == 1 && all_dealers_points.head == IdPointMap.emptyPoint){
          BigInt(1)
        } else {
          LagrangeInterpolation.getLagrangeCoeff(context.group, share.dealerPoint, all_dealers_points)
        }
    }

    val ownSharesSum =
      ownShares.zip(lambdas).foldLeft(BigInt(0)){
        case (sum, (share, lambda)) =>
          (sum + lambda * share.f_share.value).mod(modulus)
    }
    (
      Share(IdPointMap.toPoint(ownId), ownSharesSum),
      DecryptionProofData(
        ownSharesSum, // sum (or linear combination for Maintenance round > 1) of own decrypted shares
        ownSecretShares.map(_.S), // set of encrypted shares
        lambdas // set of Lagrange coefficients used in linear combination of shares: ownSharesSum
      )
    )
  }

  // Generates CorrectSharesEncryption NIZK-proof for a given set of encrypted shares
  def getSharesEncProof(crs: CorrectSharesEncryption.CRS,
                        group: DiscreteLogGroup,
                        F: (Polynomial, Polynomial),
                        shares_enc: (Seq[EncryptionProofData], Seq[EncryptionProofData])):
  CorrectSharesEncryption.Proof = {
    // Shares encryptions should be ordered accordingly to the order of evaluation points of the original shares;
    // Public keys correspond to evaluation points due to both of them are unique attributes of each party
    // Thus ordering by evaluation points implies the same order of public keys

    val evaluationPoints = shares_enc._1.map(_.eval_point)
    val pubKeys = shares_enc._1.map(_.pubKey)
    // Verifying that public keys and evaluation points order is the same for shares_enc._1 and shares_enc._2
    assert(evaluationPoints == shares_enc._2.map(_.eval_point))
    assert(pubKeys == shares_enc._2.map(_.pubKey))

    // Extract RNCE-encryptions of shares
    val ct1_ct2_seq = shares_enc._1.map(_.share_enc._1).zip(shares_enc._2.map(_.share_enc._1))
    // Extract RNCE-randomnesses used for shares encryption
    val r1_r2_seq = shares_enc._1.map(_.share_enc._2).zip(shares_enc._2.map(_.share_enc._2))

    val statement = CorrectSharesEncryption.Statement(
      ct1_ct2_seq,
      pubKeys,
      evaluationPoints
    )

    val witness = CorrectSharesEncryption.Witness(
      r1_r2_seq,
      F._1.polynomial, F._2.polynomial // passing all the coefficients of both polynomials
    )

    val cse = CorrectSharesEncryption(crs, statement, group)
    val proof = cse.prove(witness)
    // Checking that proof is correct
    assert(cse.verify(proof))
    proof
  }

  def getSharesDecProof(crs: CorrectSharesDecryption.CRS,
                        group: DiscreteLogGroup,
                        keyPair: RnceKeyPair,
                        sharesData: (DecryptionProofData, DecryptionProofData)):
  CorrectSharesDecryption.Proof = {

    val (sk, pk) = keyPair
    val lambda = group.createRandomNumber // Hash(Delta_0, Delta_1, ... Delta_t)

    val gammas = sharesData._1.gammas
    assert(gammas == sharesData._2.gammas)

    val statement = CorrectSharesDecryption.Statement(
      sharesData._1.shares_enc,
      sharesData._2.shares_enc,
      lambda,
      gammas
    )

    val witness = Witness(
      sharesData._1.shares_sum,
      sharesData._2.shares_sum,
      sk
    )

    val csd = CorrectSharesDecryption(crs, statement, group)
    val proof = csd.prove(witness)
    // Checking that proof is correct
    assert(csd.verify(proof, pk))
    proof
  }
}
