package treasury.crypto.nizk

import java.math.BigInteger

import treasury.crypto.core
import treasury.crypto.core._
import treasury.crypto.nizk.shvzk.{SHVZKGen, SHVZKVerifier}
import treasury.crypto.nizk.unitvectornizk.MultRelationNIZK

class MultRelationNIZKPerformance {

  val cs = new Cryptosystem
  val (privKey, pubKey) = cs.createKeyPair

  def createUnitVector(size: Int, choice: Int): (Seq[Ciphertext], Seq[Randomness]) = {
    assert(size > choice)
    val t = for (i <- 0 until size) yield {
      val rand = cs.getRand
      val ciphertext = cs.encrypt(pubKey, rand, if(choice == i) One else Zero)
      (ciphertext, rand)
    }
    (t.map(_._1), t.map(_._2))
  }

  def run(unitVectorSize: List[Int]): Unit = {
    for (size <- unitVectorSize) {
      println("Running test for unit vector of size " + size + " ...")
      val (uv, rand) = TimeUtils.time("\tUV creation: ", createUnitVector(size, 3))
      val value = cs.encrypt(pubKey, cs.getRand, BigInteger.valueOf(5))
      val unitVector = for(i <- 0 until size) yield if(i == 3) core.One else core.Zero
      val uv2 = TimeUtils.time("\tUV with value creation: ",
        MultRelationNIZK.produceEncryptedUnitVectorWithValue(cs, pubKey, value, unitVector))
      val proof = TimeUtils.time(
        "\tMultiplicative relation NIZK creation: ",
         MultRelationNIZK.produceNIZK(cs, pubKey, value, unitVector, rand, uv2.map(_._2)))
      val verified = TimeUtils.time(
        "\tMultiplicative relation verification",
        MultRelationNIZK.verifyNIZK(cs, pubKey, value, uv, uv2.map(_._1), proof))
      println("\tVerified: " + verified)
      println("\tProof size: " + proof.size + " bytes")
    }
  }

  def runWithAccurateTime(unitVectorSize: List[Int]): Unit = {
    for (size <- unitVectorSize) {
      println("Running test for unit vector of size " + size + " ...")
      val (uv, rand) = TimeUtils.time("\tUV creation: ", createUnitVector(size, 3))
      val value = cs.encrypt(pubKey, cs.getRand, BigInteger.valueOf(5))
      val unitVector = for(i <- 0 until size) yield if(i == 3) core.One else core.Zero
      val uv2 = TimeUtils.time("\tUV with value creation: ",
        MultRelationNIZK.produceEncryptedUnitVectorWithValue(cs, pubKey, value, unitVector))

      val proof = MultRelationNIZK.produceNIZK(cs, pubKey, value, unitVector, rand, uv2.map(_._2))
      TimeUtils.accurate_time("\tMultiplicative relation NIZK creation: ",
        MultRelationNIZK.produceNIZK(cs, pubKey, value, unitVector, rand, uv2.map(_._2)))

      TimeUtils.accurate_time(
        "\tMultiplicative relation NIZK verification",
        MultRelationNIZK.verifyNIZK(cs, pubKey, value, uv, uv2.map(_._1), proof))

      println("\tNIZK Proof size: " + proof.size + " bytes")
    }
  }
}

object MultRelationNIZKPerformance {
  def main(args: Array[String]) {
    val unitVectorSize = List(255, 511, 1023, 2047, 4095)
    //new MultRelationNIZKPerformance().run(unitVectorSize)

    val unitVectorSize2 = List(8, 16, 32, 64, 128, 256, 512, 1024)
    new MultRelationNIZKPerformance().runWithAccurateTime(unitVectorSize2)
  }
}