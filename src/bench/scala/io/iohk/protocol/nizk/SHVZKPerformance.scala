package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKVerifier}

import scala.collection.mutable.ArrayBuffer
import scala.util.Random

// Performance of the UV NIZK proof of log(n) size (n is a UV's length)
class SHVZKPerformance {

  private val context = new CryptoContext(None)
  import context.{group, hash, commonReferenceString}

  def run(vectorSize: Int): Unit = {
    val sampleSize = 100

    val pubKey = encryption.createKeyPair.get._2

    // Creating a random binary vector of specified length
    val unitVector = ArrayBuffer.fill[BigInt](vectorSize - 1)(BigInt(0))
    val uvIndex = Random.nextInt(vectorSize)
    unitVector.insert(uvIndex, BigInt(1))
    val encUnitVector = unitVector.map(LiftedElGamalEnc.encrypt(pubKey, _).get)

    println(s"Vector size: $vectorSize ---------------------------------")

    val nizkProver = new SHVZKGen(commonReferenceString, pubKey,
      encUnitVector.map(_._1),
      uvIndex, // index corresponding to the ranking UV
      encUnitVector.map(_._2)
    )
    val nizkVerifier = new SHVZKVerifier(commonReferenceString, pubKey,
      encUnitVector.map(_._1),
      nizkProver.produceNIZK().get
    )
    assert(nizkVerifier.verifyProof()) // warming up

    val (proofs, proverTime) = TimeUtils.get_time_average_s(
      "UVLog prover time:",
      (0 until sampleSize).map(_ => nizkProver.produceNIZK().get),
      sampleSize
    )
    assert(proofs.length == sampleSize)

    println
    val (results, verifierTime) = TimeUtils.get_time_average_s(
      "UVLog verifier time:",
      proofs.map(
        new SHVZKVerifier(commonReferenceString, pubKey,
          encUnitVector.map(_._1), _
        ).verifyProof()
      ),
      proofs.length
    )
    assert(results.forall(_.equals(true)))
    println("\nUVLog proof size: " + (SizeUtils.getMaxSize(proofs).toFloat / 1024) + " KB")
  }

  def start(): Unit = {
    List(10, 20, 40, 80, 160).foreach(run)
  }
}

object SHVZKPerformance {
  def main(args: Array[String]): Unit = {
    new SHVZKPerformance().start()
  }
}
