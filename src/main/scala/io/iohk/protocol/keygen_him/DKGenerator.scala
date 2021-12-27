package io.iohk.protocol.keygen_him

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.common.commitment.PedersenCommitment
import io.iohk.protocol.common.datastructures.{SecretShare, Share}
import io.iohk.protocol.common.dlog_encryption.{DLogEncryption, DLogRandomness}
import io.iohk.protocol.common.him.HIM
import io.iohk.protocol.common.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.evaluateLiftedPoly
import io.iohk.protocol.keygen_him.DKGenerator.{decryptShares, encryptShares, getShares}
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharing
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharing.{Statement, Witness}
import io.iohk.protocol.keygen_him.datastructures.{R1Data, R2Data}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

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

case class Complaint(senderID: Int)

case class DKGenerator(context:    CryptoContext,
                       crs:        Seq[GroupElement],
                       ownKeyPair: KeyPair,
                       allPubKeys: Seq[PubKey],
                       alphas:     Seq[BigInt],
                       betas:      Seq[BigInt]) {
  assert(crs.nonEmpty)
  assert(allPubKeys.nonEmpty)
  assert(alphas.size == allPubKeys.size) // number of alphas is the same as the total number of parties
  assert(betas.nonEmpty) // number of betas implicitly defines the number of public keys to be generated
  assert(allPubKeys.contains(ownKeyPair._2)) // own key-pair should be a one of a participating party

  private val params = SharingParameters(allPubKeys)
  val partialSK = context.group.createRandomNumber
  private val polynomial = Polynomial(context.group, params.t - 1, partialSK)

  implicit private val group: DiscreteLogGroup = context.group
  private val g = group.groupGenerator
  private val h = crs.head
  private val commitment = PedersenCommitment(g, h)
  val ownID = params.keyToIdMap.getId(ownKeyPair._2).get

  private var receivedShares = ArrayBuffer[(Int, BigInt)]() // sorted by a senderID (SenderID, share-value) tuples for QUAL members
  private var partialSKs = ArrayBuffer[BigInt]() // actually the shares of the global SKs computed by multiplication with HIM
  private var coeffsCommitments = ArrayBuffer[(Int, Seq[GroupElement])]() // sorted by a senderID sets of commitments of all polynomial coefficients (g^a_i) received from parties in QUAL

  def getPartialSKs(): Seq[BigInt] = {
    partialSKs
  }

  def round1(): R1Data = {
    val c_rand = polynomial.coeffs().map(c => (c, group.createRandomNumber))
    val C = c_rand.map{ case(c, r) => commitment.get(c, r) }

    val shares = getShares(polynomial, params.allIds.map(IdPointMap.toPoint))
    val encShares_rand = encryptShares(context, shares, params.keyToIdMap)

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

  def round2(r1Data: Seq[R1Data]): R2Data = {
    assert(r1Data.size <= params.n) // the number of posted R1Data-messages can't exceed the total number of parties

    assert(
      r1Data.forall{d =>
        CorrectSharing(
          h,
          allPubKeys,
          Statement(d.coeffsCommitments, d.encShares)
        ).verify(d.proofNIZK)
      }
    )

    val senderID_encShares = r1Data.map{ d =>
      // All shares posted by each party should be for different receiving parties
      assert(d.encShares.map(_.receiverID).distinct.size == d.encShares.size)
      // Take the encrypted share for own ID
      (d.senderID, d.encShares.filter(_.receiverID == ownID).head)
    }

    val senderIDs = senderID_encShares.map(_._1)
    val encShares = senderID_encShares.map(_._2)
    assert(receivedShares.isEmpty)
    receivedShares ++= senderIDs.zip(decryptShares(context, encShares, ownKeyPair._1).get.map(_.value)).sortBy(_._1)

    val him = HIM(alphas.take(receivedShares.size), betas)
    assert(partialSKs.isEmpty)
    partialSKs ++= him.mul(receivedShares.map(_._2))

    val D = polynomial.coeffs().map(c => commitment.get(c, BigInt(0)))
    R2Data(ownID, D)
  }

  def round3(r2Data: Seq[R2Data]): Seq[Complaint] = {
    // TODO: Filter out r2Data from disqualified parties
    val ownEvalPoint = BigInt(IdPointMap.toPoint(ownID))
    val complaints = r2Data.flatMap{ d =>
      if (evaluateLiftedPoly(d.coeffsCommitments, ownEvalPoint) !=
        g.pow(receivedShares.find(_._1 == d.senderID).get._2).get) {
        Some(Complaint(ownID))
      } else {
        coeffsCommitments += Tuple2(d.senderID, d.coeffsCommitments)
        None
      }
    }
    // Sort all sets of received commitments by IDs of their senders
    coeffsCommitments = coeffsCommitments.sortBy(_._1)
    complaints
  }

  def globalPubKeys(): Seq[GroupElement] = {
    val him = HIM(alphas.take(receivedShares.size), betas)
    him.mulLifted(coeffsCommitments.map(_._2.head)) // multiply HIM by a vector of a0-commitments of each party
  }
}

object DKGenerator {

  def getShares(poly: Polynomial, evaluationPoints: Seq[Int]) : Seq[Share] = {
    evaluationPoints.map{
      point =>
        assert(point != 0) // avoid disclosing a_0 coefficient
        Share(point, poly.evaluate(point))
    }
  }

  def reconstructSecret(context: CryptoContext,
                        all_shares: Seq[Share]): BigInt = {
    LagrangeInterpolation.restoreSecret(context.group, all_shares)
  }

  def encryptShares(context: CryptoContext,
                    shares: Seq[Share],
                    keyToIdMap: CommitteeIdentifier): Seq[(SecretShare, DLogRandomness)] = {
    import context.group

    shares.map{
      share =>
        val receiverId = IdPointMap.toId(share.point)
        val receiverPubKey = keyToIdMap.getPubKey(receiverId).get
        val encShare = DLogEncryption.encrypt(share.value, receiverPubKey).get;
        (
          SecretShare(
            receiverId,
            encShare._1
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
        val share = DLogEncryption.decrypt(secretShare.S, privKey).get
        val point = IdPointMap.toPoint(secretShare.receiverID)
        Share(point, share)
    }
  }
}
