package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.commitment.PedersenCommitment
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.secret_sharing.ShamirSecretSharing.{IdPointMap, SharingParameters, encryptShares, getShares}
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.CorrectSharing
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.CorrectSharing.{Statement, Witness}


class CorrectSharingPerformance {

  private val context = new CryptoContext(None)
  import context.group

  private val g = group.groupGenerator
  private val h = CryptoContext.generateRandomCRS
  private val commitment = PedersenCommitment(g, h)

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  def run(membersNum: Int): Unit = {
    val sampleSize = 100

    val keys = generateKeys(membersNum)
    val pubKeys = keys.map(_._2)

    val params = SharingParameters(pubKeys)
    val secret = group.createRandomNumber

    val polynomial = Polynomial(group, params.t - 1, secret)
    val c_rand = polynomial.coeffs().map(c => (c, group.createRandomNumber))
    val coeffsCommitments = c_rand.map{ case(c, r) => commitment.get(c, r) }

    // Generating share for each committee member
    val shares = getShares(polynomial, params.allIds.map(IdPointMap.toPoint))
    val encShares_rand = encryptShares(context, shares, params)

    assert(shares.length == encShares_rand.length && shares.length == membersNum)

    println(s"Committee size: $membersNum ---------------------------------")

    val st = Statement(coeffsCommitments, encShares_rand.map(_._1))
    val w = Witness(shares.zip(encShares_rand.map(_._2.R)), c_rand.map(_._2))

    val nizk = CorrectSharing(h, pubKeys, st)
    assert(nizk.verify(nizk.prove(w))) // warming up

    val (proofs, proverTime) = TimeUtils.get_time_average_s(
      "CorrectSharing prover time:",
      (0 until sampleSize).map(_ => nizk.prove(w)),
      sampleSize
    )
    assert(proofs.length == sampleSize)

    println
    val (results, verifierTime) = TimeUtils.get_time_average_s(
      "CorrectSharing verifier time:",
      proofs.map(nizk.verify),
      proofs.length
    )
    assert(results.forall(_.equals(true)))

    println("\nCorrectSharing proof size: " + (SizeUtils.getMaxSize(proofs).toFloat / 1024) + " KB")
  }

  def start(): Unit = {
    List(10, 20, 40, 80, 160).foreach(run)
  }
}

object CorrectSharingPerformance {
  def main(args: Array[String]): Unit = {
    new CorrectSharingPerformance().start()
  }
}
