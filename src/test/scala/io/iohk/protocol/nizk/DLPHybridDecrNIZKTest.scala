package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption._
import io.iohk.core.crypto.encryption.elgamal.ElGamalEnc
import io.iohk.core.crypto.encryption.hybrid.dlp.DLPHybridEncryption
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class DLPHybridDecrNIZKTest extends FunSuite {

  val ctx = new CryptoContext(None)
  implicit val group = ctx.group
  implicit val hash = ctx.hash
  implicit val blockCipher = ctx.blockCipher

  test("hybrid decryption nizk") {
    val (privKey, pubKey) = createKeyPair.get
    val message = "Message".getBytes
    val ciphertext = DLPHybridEncryption.encrypt(pubKey, message).get
    val decrypted = DLPHybridEncryption.decrypt(privKey, ciphertext).get

    assert(message.sameElements(decrypted))

    val proof = DLPHybridDecrNIZK.produceNIZK(ciphertext, privKey).get
    val verified = DLPHybridDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, proof)

    assert(verified)

    val corruptedProof = DLPHybridDecrNIZKProof(proof.decryptedKey,
      DLEQStandardNIZKProof(proof.dleqProof.A1, proof.dleqProof.A2, proof.dleqProof.z + 1))
    assert(!DLPHybridDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, corruptedProof))

    val corruptedProof2 = DLPHybridDecrNIZKProof(proof.decryptedKey.pow(privKey).get, proof.dleqProof)
    assert(!DLPHybridDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, corruptedProof2))
    decrypted(0) = (decrypted(0)+1).toByte // corrupting decrypted text
    assert(!DLPHybridDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, proof))
  }

  test("serialization") {
    val (privKey, pubKey) = createKeyPair.get
    val plaintext = "Message".getBytes
    val ciphertext = DLPHybridEncryption.encrypt(pubKey, plaintext).get
    val decrypted = DLPHybridEncryption.decrypt(privKey, ciphertext).get

    assert(plaintext.sameElements(decrypted))

    val bytes = DLPHybridDecrNIZK.produceNIZK(ciphertext, privKey).get.bytes
    val proof = DLPHybridDecrNIZKProofSerializer.parseBytes(bytes, Option(group)).get

    val verified = DLPHybridDecrNIZK.verifyNIZK(pubKey, ciphertext, decrypted, proof)

    assert(verified)
  }
}
