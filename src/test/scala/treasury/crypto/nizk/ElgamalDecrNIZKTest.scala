package treasury.crypto.nizk

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.core.Cryptosystem

class ElgamalDecrNIZKTest extends FunSuite {
  test("elgamal decryption nizk") {
    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair
    val plaintext = cs.basePoint.multiply(cs.getRand)
    val ciphertext = cs.encryptPoint(pubKey, cs.getRand, plaintext)
    val decrypted = cs.decryptPoint(privKey, ciphertext)

    assert(plaintext.equals(decrypted))

    val proof = ElgamalDecrNIZK.produceNIZK(cs, ciphertext, privKey)
    val verified = ElgamalDecrNIZK.verifyNIZK(cs, pubKey, ciphertext, decrypted, proof)

    assert(verified)

    val corruptedProof = ElgamalDecrNIZKProof(proof.A1, proof.A2, proof.z.add(BigInteger.ONE))
    val res = ElgamalDecrNIZK.verifyNIZK(cs, pubKey, ciphertext, decrypted, corruptedProof)

    assert(!res)
  }

  test("inversion") {
    val cs = new Cryptosystem
    val scalar = cs.getRand
    val mult = cs.basePoint.multiply(scalar)
    val recover = mult.multiply(scalar.modInverse(cs.orderOfBasePoint))

    val res = cs.basePoint.equals(recover)
    assert(res)
  }

  test("serialization") {
    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair
    val plaintext = cs.basePoint.multiply(cs.getRand)
    val ciphertext = cs.encryptPoint(pubKey, cs.getRand, plaintext)
    val decrypted = cs.decryptPoint(privKey, ciphertext)

    assert(plaintext.equals(decrypted))

    val bytes = ElgamalDecrNIZK.produceNIZK(cs, ciphertext, privKey).bytes
    val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes, Option(cs)).get

    val verified = ElgamalDecrNIZK.verifyNIZK(cs, pubKey, ciphertext, decrypted, proof)

    assert(verified)
  }
}
