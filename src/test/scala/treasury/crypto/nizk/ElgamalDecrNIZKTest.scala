package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.encryption.elgamal.ElGamalEnc
import treasury.crypto.core.encryption.encryption._

class ElgamalDecrNIZKTest extends FunSuite {

  val cs = new Cryptosystem
  implicit val group = cs.group
  implicit val hash = cs.hash

  test("elgamal decryption nizk") {
    val (privKey, pubKey) = createKeyPair.get
    val plaintext = group.createRandomGroupElement.get
    val ciphertext = ElGamalEnc.encrypt(pubKey, plaintext).get._1
    val decrypted = ElGamalEnc.decrypt(privKey, ciphertext).get

    assert(plaintext.equals(decrypted))

    val proof = ElgamalDecrNIZK.produceNIZK(ciphertext, privKey).get
    val verified = ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, proof)

    assert(verified)

    val corruptedProof = ElgamalDecrNIZKProof(proof.A1, proof.A2, proof.z + 1)
    val res = ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, corruptedProof)

    assert(!res)
  }

  test("serialization") {
    val (privKey, pubKey) = createKeyPair.get
    val plaintext = group.createRandomGroupElement.get
    val ciphertext = ElGamalEnc.encrypt(pubKey, plaintext).get._1
    val decrypted = ElGamalEnc.decrypt(privKey, ciphertext).get

    assert(plaintext.equals(decrypted))

    val bytes = ElgamalDecrNIZK.produceNIZK(ciphertext, privKey).get.bytes
    val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes, Option(group)).get

    val verified = ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, proof)

    assert(verified)
  }
}
