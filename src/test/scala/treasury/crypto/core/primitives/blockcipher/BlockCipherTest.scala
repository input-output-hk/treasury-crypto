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

  property("any cipher should deterministically generate keys from seed") {
    forAll(ciphers) { cipher =>
      val key1 = cipher.generateKey("seedA".getBytes).asInstanceOf[AESSecretKey]
      val key2 = cipher.generateKey("seedA".getBytes).asInstanceOf[AESSecretKey]

      key1.key.sameElements(key2.key) should be (true)

      val key3 = cipher.generateKey("seedB".getBytes).asInstanceOf[AESSecretKey]
      val key4 = cipher.generateKey("seedC".getBytes).asInstanceOf[AESSecretKey]

      key3.key.sameElements(key4.key) should be (false)
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
