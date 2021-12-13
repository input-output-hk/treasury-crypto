package io.iohk.protocol.nizk

import org.scalatest.FunSuite
import io.iohk.core.crypto.encryption.elgamal.ElGamalEnc
import io.iohk.core.crypto.encryption._
import io.iohk.protocol.CryptoContext

class ElgamalDecrNIZKTest extends FunSuite {

  val ctx = new CryptoContext(None)
  implicit val group = ctx.group
  implicit val hash = ctx.hash

  test("elgamal decryption nizk") {
    val (privKey, pubKey) = createKeyPair.get
    val plaintext = group.createRandomGroupElement.get
    val ciphertext = ElGamalEnc.encrypt(pubKey, plaintext).get._1
    val decrypted = ElGamalEnc.decrypt(privKey, ciphertext).get

    assert(plaintext.equals(decrypted))

    val proof = ElgamalDecrNIZK.produceNIZK(ciphertext, privKey).get
    assert(ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, proof))

    val corruptedProof = DLEQStandardNIZKProof(proof.A1, proof.A2, proof.z + 1)
    assert(!ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, corruptedProof))
    assert(!ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted.pow(2).get, proof))
  }
}
