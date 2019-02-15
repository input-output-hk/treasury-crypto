package treasury.crypto.core.primitives.blockcipher

import org.scalatest.prop.TableDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import treasury.crypto.core.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers

class BlockCipherTest extends PropSpec with TableDrivenPropertyChecks with Matchers {

  val ciphers =
    Table(
      "cipher",
      BlockCipherFactory.constructBlockCipher(AvailableBlockCiphers.AES128_BSM_Bc).get
    )

  property("any cipher should support key generation") {
    forAll(ciphers) { cipher =>
      val key1 = cipher.generateKey.bytes
      val key2 = cipher.generateKey.bytes

      key1.size should be (cipher.keySize)
      key2.size should be (cipher.keySize)
      key1.sameElements(key2) should be (false)
    }
  }

  property("any cipher should encrypt and decrypt data") {
    forAll(ciphers) { cipher =>
      val key = cipher.generateKey
      val msg = "Test msg".getBytes

      val ciphertext = cipher.encrypt(key, msg).get
      val decryptedMsg = cipher.decrypt(key, ciphertext).get

      decryptedMsg.sameElements(msg) should be (true)
    }
  }
}
