package io.iohk.nizk

import java.math.BigInteger

import io.iohk.core._
import io.iohk.core.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.primitives.hash.CryptographicHashFactory
import io.iohk.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.nizk.unitvectornizk.MultRelationNIZK

class MultRelationNIZKPerformance {

  implicit val group = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  implicit val hash = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  val (privKey, pubKey) = encryption.createKeyPair.get

  def createUnitVector(size: Int, choice: Int): (Seq[Ciphertext], Seq[Randomness]) = {
    assert(size > choice)
    val t = for (i <- 0 until size) yield {
      val rand = group.createRandomNumber
      val ciphertext = LiftedElGamalEnc.encrypt(pubKey, rand, if(choice == i) 1 else 0).get
      (ciphertext, rand)
    }
    (t.map(_._1), t.map(_._2))
  }

  def run(unitVectorSize: List[Int]): Unit = {
    for (size <- unitVectorSize) {
      println("Running test for unit vector of size " + size + " ...")
      val (uv, rand) = TimeUtils.time("\tUV creation: ", createUnitVector(size, 3))
      val value = LiftedElGamalEnc.encrypt(pubKey, BigInteger.valueOf(5)).get._1
      val unitVector = for(i <- 0 until size) yield if(i == 3) BigInt(1) else BigInt(0)
      val uv2 = TimeUtils.time("\tUV with value creation: ",
        MultRelationNIZK.produceEncryptedUnitVectorWithValue(pubKey, value, unitVector))
      val proof = TimeUtils.time(
        "\tMultiplicative relation NIZK creation: ",
         MultRelationNIZK.produceNIZK(pubKey, value, unitVector, rand, uv2.map(_._2)).get)
      val verified = TimeUtils.time(
        "\tMultiplicative relation verification",
        MultRelationNIZK.verifyNIZK(pubKey, value, uv, uv2.map(_._1), proof))
      println("\tVerified: " + verified)
      println("\tProof size: " + proof.size + " bytes")
    }
  }

  def runWithAccurateTime(unitVectorSize: List[Int]): Unit = {
    for (size <- unitVectorSize) {
      println("Running test for unit vector of size " + size + " ...")
      val (uv, rand) = TimeUtils.time("\tUV creation: ", createUnitVector(size, 3))
      val value = LiftedElGamalEnc.encrypt(pubKey, BigInteger.valueOf(5)).get._1
      val unitVector = for(i <- 0 until size) yield if(i == 3) BigInt(1) else BigInt(0)
      val uv2 = TimeUtils.time("\tUV with value creation: ",
        MultRelationNIZK.produceEncryptedUnitVectorWithValue(pubKey, value, unitVector))

      val proof = MultRelationNIZK.produceNIZK(pubKey, value, unitVector, rand, uv2.map(_._2)).get
      TimeUtils.accurate_time("\tMultiplicative relation NIZK creation: ",
        MultRelationNIZK.produceNIZK(pubKey, value, unitVector, rand, uv2.map(_._2)).get)

      TimeUtils.accurate_time(
        "\tMultiplicative relation NIZK verification",
        MultRelationNIZK.verifyNIZK(pubKey, value, uv, uv2.map(_._1), proof))

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