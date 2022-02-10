package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne.{Statement, Witness}

import scala.util.Random

class BatchedZeroOrOnePerformance {

  private val context = new CryptoContext(None)
  import context.group


  def run(vectorSize: Int): Unit = {
    val sampleSize = 100

    val pubKey = encryption.createKeyPair.get._2

    // Creating a random binary vector of specified length
    val binaryVec = (0 until vectorSize).map(_ => BigInt(Random.nextInt(2)))
    val encBinaryVec = binaryVec.map(LiftedElGamalEnc.encrypt(pubKey, _).get)

    println(s"Vector size: $vectorSize ---------------------------------")

    val st = Statement(pubKey, encBinaryVec.map(_._1))
    val w = Witness(binaryVec, encBinaryVec.map(_._2))

    val nizk = BatchedZeroOrOne(st)
    assert(nizk.verify(nizk.prove(w))) // warming up

    val (proofs, proverTime) = TimeUtils.get_time_average_s(
      "BatchedZeroOrOne prover time:",
      (0 until sampleSize).map(_ => nizk.prove(w)),
      sampleSize
    )
    assert(proofs.length == sampleSize)

    println
    val (results, verifierTime) = TimeUtils.get_time_average_s(
      "BatchedZeroOrOne verifier time:",
      proofs.map(nizk.verify),
      proofs.length
    )
    assert(results.forall(_.equals(true)))
    println("\nBatchedZeroOrOne proof size: " + (SizeUtils.getMaxSize(proofs).toFloat / 1024) + " KB")
  }

  def start(): Unit = {
    List(10, 20, 40, 80, 160).foreach(run)
  }
}

object BatchedZeroOrOnePerformance {
  def main(args: Array[String]): Unit = {
    new BatchedZeroOrOnePerformance().start()
  }
}
