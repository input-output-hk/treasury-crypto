package treasury.crypto.nizk

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.core.{Cryptosystem, One, Zero}
import treasury.crypto.nizk.unitvectornizk.ZeroOrOneBZNIZK

class ZeroOrOneBZNIZKTest extends FunSuite {
  private val cs = new Cryptosystem
  private val (privKey, pubKey) = cs.createKeyPair

  test("encrypt one") {
    val r = cs.getRand
    val c = cs.encrypt(pubKey, r, One)

    val proof = ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, One, c, r)
    val verified = ZeroOrOneBZNIZK.verifyNIZK(cs, pubKey, c, proof)

    assert(verified)
  }

  test("encrypt zero") {
    val r = cs.getRand
    val c = cs.encrypt(pubKey, r, Zero)

    val proof = ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, Zero, c, r)
    val verified = ZeroOrOneBZNIZK.verifyNIZK(cs, pubKey, c, proof)

    assert(verified)
  }

  test("encrypt two") {
    val m = BigInteger.valueOf(2)
    val r = cs.getRand
    val c = cs.encrypt(pubKey, r, m)

    val proof = ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, m, c, r)
    val verified = ZeroOrOneBZNIZK.verifyNIZK(cs, pubKey, c, proof)

    assert(verified == false)
  }

  test("encrypt -1") {
    val m = BigInteger.valueOf(-1)
    val r = cs.getRand
    val c = cs.encrypt(pubKey, r, m)

    val proof = ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, m, c, r)
    val verified = ZeroOrOneBZNIZK.verifyNIZK(cs, pubKey, c, proof)

    assert(verified == false)
  }

  test("inconsistent ciphertext") {
    val r = cs.getRand
    val c = cs.encrypt(pubKey, r, Zero)

    val proof = ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, One, c, r)
    val verified = ZeroOrOneBZNIZK.verifyNIZK(cs, pubKey, c, proof)

    assert(verified == false)
  }
}
