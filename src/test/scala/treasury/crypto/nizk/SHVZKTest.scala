package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto.core._
import treasury.crypto.nizk.shvzk.{SHVZKCommon, SHVZKGen, SHVZKProofCompanion, SHVZKVerifier}

class SHVZKTest extends FunSuite {

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

  test("unit vector padding") {
    val choice = 6
    val (uv, rand) = createUnitVector(13, choice)
    val nizk = new SHVZKGen(cs, pubKey, uv, choice, rand)

    val paddedUv = nizk.padUnitVector(uv)
    val paddedRand = nizk.padRandVector(rand)

    assert(paddedRand.size == paddedUv.size)
    assert(paddedUv.size == 16)
    assert(paddedRand(13).equals(Zero))
    assert(paddedUv(13) == paddedUv(14))
    assert(paddedUv(14) == paddedUv(15))
  }

  test("int to bin array") {
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

  test("produce nizk") {
    val choice = 3
    val (uv, rand) = createUnitVector(13, choice)

    val proof = new SHVZKGen(cs, pubKey, uv, choice, rand).produceNIZK()
    val verified = new SHVZKVerifier(cs, pubKey, uv, proof).verifyProof()

    assert(verified)
  }

  test("produce nizk 2") {
    val choice = 2
    val (uv, rand) = createUnitVector(3, choice)

    val proof = new SHVZKGen(cs, pubKey, uv, choice, rand).produceNIZK()
    val verified = new SHVZKVerifier(cs, pubKey, uv, proof).verifyProof()

    assert(verified)
  }

  test("produce nizk 3") {
    val choice = 62
    val (uv, rand) = createUnitVector(64, choice)

    val proof = new SHVZKGen(cs, pubKey, uv, choice, rand).produceNIZK()
    val verified = new SHVZKVerifier(cs, pubKey, uv, proof).verifyProof()

    assert(verified)
  }

  test("proof size") {
    val choice = 0
    val (uv, rand) = createUnitVector(5, choice)
    val proof = new SHVZKGen(cs, pubKey, uv, choice, rand).produceNIZK()

    assert(proof.IBA.size == 3)
    assert(proof.Dk.size == 3)
    assert(proof.zwv.size == 3)
  }

  test("proof size 2") {
    val choice = 3
    val (uv, rand) = createUnitVector(16, choice)
    val proof = new SHVZKGen(cs, pubKey, uv, choice, rand).produceNIZK()

    assert(proof.IBA.size == 4)
    assert(proof.Dk.size == 4)
    assert(proof.zwv.size == 4)
  }

  test("serialization") {
    val (uv, rand) = createUnitVector(5, 0)
    val proofBytes = new SHVZKGen(cs, pubKey, uv, 0, rand).produceNIZK().bytes
    val proof = SHVZKProofCompanion.parseBytes(proofBytes, cs)

    assert(new SHVZKVerifier(cs, pubKey, uv, proof.get).verifyProof())
  }
}
