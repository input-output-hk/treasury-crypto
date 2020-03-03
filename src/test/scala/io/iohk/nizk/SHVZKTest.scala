package io.iohk.nizk

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import io.iohk.core.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.encryption
import io.iohk.core.encryption.{PubKey, Randomness}
import io.iohk.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.core.primitives.hash.CryptographicHashFactory
import io.iohk.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.nizk.shvzk.{SHVZKCommon, SHVZKGen, SHVZKProofSerializer, SHVZKVerifier}

class SHVZKTest extends FunSuite with TableDrivenPropertyChecks {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => DiscreteLogGroupFactory.constructDlogGroup(g).get):_*
    )
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  def createUnitVector(size: Int, choice: Int, pubKey: PubKey)
                      (implicit group: DiscreteLogGroup): (Seq[ElGamalCiphertext], Seq[Randomness]) = {
    assert(size > choice)
    val t = for (i <- 0 until size) yield {
      val rand = group.createRandomNumber
      val ciphertext = LiftedElGamalEnc.encrypt(pubKey, rand, if(choice == i) 1 else 0).get
      (ciphertext, rand)
    }
    (t.map(_._1), t.map(_._2))
  }

  test("unit vector padding") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get

      val choice = 6
      val (uv, rand) = createUnitVector(13, choice, pubKey)
      val nizk = new SHVZKGen(pubKey, uv, choice, rand)

      val paddedUv = nizk.padUnitVector(uv).get
      val paddedRand = nizk.padRandVector(rand)

      assert(paddedRand.size == paddedUv.size)
      assert(paddedUv.size == 16)
      assert(paddedRand(13).equals(BigInt(0)))
      assert(paddedUv(13) == paddedUv(14))
      assert(paddedUv(14) == paddedUv(15))
    }
  }

  test("int to bin array") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get
      val binArray = SHVZKCommon.intToBinArray(3, 8)

      assert(binArray.size == 8)
      assert(binArray(0) == 0)
      assert(binArray(1) == 0)
      assert(binArray(2) == 0)
      assert(binArray(3) == 0)
      assert(binArray(4) == 0)
      assert(binArray(5) == 0)
      assert(binArray(6) == 1)
      assert(binArray(7) == 1)
    }
  }

  test("produce nizk") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get
      val choice = 3
      val (uv, rand) = createUnitVector(13, choice, pubKey)

      val proof = new SHVZKGen(pubKey, uv, choice, rand).produceNIZK().get
      val verified = new SHVZKVerifier(pubKey, uv, proof).verifyProof()

      assert(verified)
    }
  }

  test("produce nizk 2") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get
      val choice = 2
      val (uv, rand) = createUnitVector(3, choice, pubKey)

      val proof = new SHVZKGen(pubKey, uv, choice, rand).produceNIZK().get
      val verified = new SHVZKVerifier(pubKey, uv, proof).verifyProof()

      assert(verified)
    }
  }

  test("produce nizk 3") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get
      val choice = 62
      val (uv, rand) = createUnitVector(64, choice, pubKey)

      val proof = new SHVZKGen(pubKey, uv, choice, rand).produceNIZK().get
      val verified = new SHVZKVerifier(pubKey, uv, proof).verifyProof()

      assert(verified)
    }
  }

  test("proof size") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get
      val choice = 0
      val (uv, rand) = createUnitVector(5, choice, pubKey)
      val proof = new SHVZKGen(pubKey, uv, choice, rand).produceNIZK.get

      assert(proof.IBA.size == 3)
      assert(proof.Dk.size == 3)
      assert(proof.zwv.size == 3)
    }
  }

  test("proof size 2") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get
      val choice = 3
      val (uv, rand) = createUnitVector(16, choice, pubKey)
      val proof = new SHVZKGen(pubKey, uv, choice, rand).produceNIZK.get

      assert(proof.IBA.size == 4)
      assert(proof.Dk.size == 4)
      assert(proof.zwv.size == 4)
    }
  }

  test("serialization") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = encryption.createKeyPair.get
      val (uv, rand) = createUnitVector(5, 0, pubKey)
      val proofBytes = new SHVZKGen(pubKey, uv, 0, rand).produceNIZK.get.bytes
      val proof = SHVZKProofSerializer.parseBytes(proofBytes, Option(group))

      assert(new SHVZKVerifier(pubKey, uv, proof.get).verifyProof)
    }
  }
}
