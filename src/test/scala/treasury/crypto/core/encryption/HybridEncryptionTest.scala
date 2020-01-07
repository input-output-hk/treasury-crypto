package treasury.crypto.core.encryption

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.encryption.hybrid.{HybridCiphertextSerializer, HybridEncryption}
import treasury.crypto.core.primitives.blockcipher.BlockCipherFactory
import treasury.crypto.core.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups

class HybridEncryptionTest extends FunSuite with TableDrivenPropertyChecks {

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

  test("HybridEncryption should correctly encrypt and decrypt message for any dlog and any block cipher") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get

        val ciphertext = HybridEncryption.encrypt(pubKey, message).get
        val decryptedMessage = HybridEncryption.decrypt(privKey, ciphertext).get._2

        require(message.sameElements(decryptedMessage))
      }
    }
  }

  test("HybridEncryption should correctly encrypt and decrypt message if secret seed is provided") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get
        val seed = "SuperSecretSeed".getBytes

        val ciphertext = HybridEncryption.encrypt(pubKey, message, seed).get
        val decryptedMessage = HybridEncryption.decrypt(privKey, ciphertext).get._2

        require(message.sameElements(decryptedMessage))
      }
    }
  }

  test("HybridEncryption should correctly encrypt and decrypt message if group element as secret seed is provided") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get
        val seedAsGroupElement = group.createRandomGroupElement.get

        val ciphertext = HybridEncryption.encrypt(pubKey, message, seedAsGroupElement).get
        val decryptedMessage = HybridEncryption.decrypt(privKey, ciphertext).get

        require(seedAsGroupElement == decryptedMessage._1)
        require(message.sameElements(decryptedMessage._2))
      }
    }
  }

  test("HybridCiphertext should support serialization") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get

        val ciphertext = HybridEncryption.encrypt(pubKey, message).get
        val bytes = ciphertext.bytes
        val reconstructedCiphertext = HybridCiphertextSerializer.parseBytes(bytes, Option(group, blockCipher)).get
        val decryptedMessage = HybridEncryption.decrypt(privKey, reconstructedCiphertext).get._2

        require(message.sameElements(decryptedMessage))
      }
    }
  }

  test("HybridCiphertext should produce the same ciphertext (by byte-to-byte comparison) provided with the same secret seed") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get
        val seedAsGroupElement = group.createRandomGroupElement.get
        val secretSeed = group.createRandomNumber.toByteArray

        val ciphertext1 = HybridEncryption.encrypt(pubKey, message, seedAsGroupElement).get
        val ciphertext2 = HybridEncryption.encrypt(pubKey, message, seedAsGroupElement).get

        require(ciphertext1.bytes.sameElements(ciphertext2.bytes))

        val ciphertext3 = HybridEncryption.encrypt(pubKey, message, secretSeed).get
        val ciphertext4 = HybridEncryption.encrypt(pubKey, message, secretSeed).get

        require(ciphertext3.bytes.sameElements(ciphertext4.bytes))
      }
    }
  }
}
