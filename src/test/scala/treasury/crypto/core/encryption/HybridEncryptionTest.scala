package treasury.crypto.core.encryption

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.dlog.DiscreteLogGroupTest
import treasury.crypto.core.encryption.hybrid.HybridEncryption
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
      BlockCipherFactory.constructBlockCipher(AvailableBlockCiphers.AES128_BSM_Bc).get
    )

  test("HybridEncryption should correctly encrypt and decrypt message for any dlog and any block cipher") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get

        val ciphertext = HybridEncryption.encrypt(pubKey, message).get
        val decryptedMessage = HybridEncryption.decrypt(privKey, ciphertext).get

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
        val decryptedMessage = HybridEncryption.decrypt(privKey, ciphertext).get

        require(message.sameElements(decryptedMessage))
      }
    }
  }
}
