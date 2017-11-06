package treasury.crypto.nizk

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.core._
import treasury.crypto.nizk.unitvectornizk.UVSumNIZK

class UVSumNIZKTest extends FunSuite {
  private val cs = new Cryptosystem
  private val (privKey, pubKey) = cs.createKeyPair

  def doTest(unitVector: Array[BigInteger]): Boolean = {
    val ciphertexts = unitVector.map { x =>
      val r = cs.getRand
      (cs.encrypt(pubKey, r, x), r)
    }

    val proof = UVSumNIZK.produceNIZK(cs, pubKey, ciphertexts)
    UVSumNIZK.verifyNIZK(cs, pubKey, ciphertexts.map(_._1), proof)
  }

  test("test for valid unitvector") {
    val unitVector = Array[BigInteger](Zero, Zero, One)
    val verified = doTest(unitVector)

    assert(verified)
  }

  test("test for valid sum") {
    val unitVector = Array[BigInteger](BigInteger.valueOf(-1), Zero, One, One)
    val verified = doTest(unitVector)

    assert(verified)
  }

  test("test for unit vector of all zeros") {
    val unitVector = Array[BigInteger](Zero, Zero, Zero)
    val verified = doTest(unitVector)

    assert(verified == false)
  }

  test("test for unit vector with incorrect sum") {
    val unitVector = Array[BigInteger](Zero, One, One)
    val verified = doTest(unitVector)

    assert(verified == false)
  }

  test("test for unit vector with negative sum") {
    val unitVector = Array[BigInteger](Zero, BigInteger.valueOf(-1), Zero)
    val verified = doTest(unitVector)

    assert(verified == false)
  }
}
