package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto._
import treasury.crypto.nizk.shvzk.{SHVZKCommon, SHVZKGen, SHVZKVerifier}

class SHVZKTest extends FunSuite {

  val cs = new EllipticCurveCryptosystem
  val (privKey, pubKey) = cs.createKeyPair()

  def createUnitVector(size: Int, choice: Int): (Seq[Ciphertext], Seq[Randomness]) = {
    assert(size > choice)
    val t = for (i <- 0 until size) yield {
      val rand = cs.getRand()
      val ciphertext = cs.encrypt(pubKey, rand, if(choice == i) 1 else 0)
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
    assert(paddedRand(13).size == 1 && paddedRand(13)(0) == 0)
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
}
