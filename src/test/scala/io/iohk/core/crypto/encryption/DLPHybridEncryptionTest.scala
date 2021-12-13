package io.iohk.core.crypto.encryption

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.hybrid.dlp.{DLPHybridEncryption, DLPHybridCiphertextSerializer}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

class DLPHybridEncryptionTest extends FunSuite with TableDrivenPropertyChecks {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => DiscreteLogGroupFactory.constructDlogGroup(g).get):_*
    )

  val blockCiphers =
    Table(
      "blockCipher",
      AvailableBlockCiphers.values.toSeq.map(c => BlockCipherFactory.constructBlockCipher(c).get):_*
    )

  test("DLPHybridEncryption should correctly encrypt and decrypt message for any dlog and any block cipher") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get

        val ciphertext = DLPHybridEncryption.encrypt(pubKey, message).get
        val decryptedMessage = DLPHybridEncryption.decrypt(privKey, ciphertext).get

        require(message.sameElements(decryptedMessage))
      }
    }
  }

  test("DLPHybridEncryption should correctly encrypt and decrypt message if secret seed is provided") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get
        val seed = "SuperSecretSeed".getBytes

        val ciphertext = DLPHybridEncryption.encrypt(pubKey, message, seed).get
        val decryptedMessage = DLPHybridEncryption.decrypt(privKey, ciphertext).get

        require(message.sameElements(decryptedMessage))
      }
    }
  }

  test("DLPHybridEncryption should correctly encrypt and decrypt message if a secret scalar is provided") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get
        val r = group.createRandomNumber

        val ciphertext = DLPHybridEncryption.encrypt(pubKey, message, r).get
        val decryptedMessage = DLPHybridEncryption.decrypt(privKey, ciphertext).get

        require(message.sameElements(decryptedMessage))
      }
    }
  }

  test("DLPHybridEncryption should support serialization") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get

        val ciphertext = DLPHybridEncryption.encrypt(pubKey, message).get
        val bytes = ciphertext.bytes
        val reconstructedCiphertext = DLPHybridCiphertextSerializer.parseBytes(bytes, Option(group, blockCipher)).get
        val decryptedMessage = DLPHybridEncryption.decrypt(privKey, reconstructedCiphertext).get

        require(message.sameElements(decryptedMessage))
      }
    }
  }

  test("DLPHybridEncryption should produce the same ciphertext (by byte-to-byte comparison) provided with the same randomness") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get
        val r = group.createRandomNumber

        val ciphertext1 = DLPHybridEncryption.encrypt(pubKey, message, r).get
        val ciphertext2 = DLPHybridEncryption.encrypt(pubKey, message, r).get

        require(ciphertext1.bytes.sameElements(ciphertext2.bytes))

        val ciphertext3 = DLPHybridEncryption.encrypt(pubKey, message, r.toByteArray).get
        val ciphertext4 = DLPHybridEncryption.encrypt(pubKey, message, r.toByteArray).get

        require(ciphertext3.bytes.sameElements(ciphertext4.bytes))
      }
    }
  }
}
