package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto.core.Cryptosystem

class DecryptionShareNIZKTest extends FunSuite {
  test("valid nizk") {
    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair

    val share = cs.basePoint.multiply(cs.getRand)
    val decryptedShare = share.multiply(privKey)

    val proof = DecryptionShareNIZK.produceNIZK(cs, share, privKey)
    val verified = DecryptionShareNIZK.verifyNIZK(cs, pubKey, share, decryptedShare, proof)

    assert(verified)
  }

  test("test wrong decryption") {
    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair

    val share = cs.basePoint.multiply(cs.getRand)
    val decryptedShare = share.multiply(cs.getRand) // use wrong key to decrypt

    val proof = DecryptionShareNIZK.produceNIZK(cs, share, privKey)
    val verified = DecryptionShareNIZK.verifyNIZK(cs, pubKey, share, decryptedShare, proof)

    assert(verified == false)
  }

  test("test invalid share") {
    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair

    val share = cs.basePoint.multiply(cs.getRand)
    val decryptedShare = share.multiply(cs.getRand) // use wrong key to decrypt

    val proof = DecryptionShareNIZK.produceNIZK(cs, share, privKey)
    val verified = DecryptionShareNIZK.verifyNIZK(cs, pubKey, share.multiply(cs.getRand), decryptedShare, proof)

    assert(verified == false)
  }
}
