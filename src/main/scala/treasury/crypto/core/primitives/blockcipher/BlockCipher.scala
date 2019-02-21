package treasury.crypto.core.primitives.blockcipher

import treasury.crypto.core.primitives.blockcipher.BlockCipher.{Ciphertext, SecretKey}
import treasury.crypto.core.serialization.BytesSerializable

import scala.util.Try

trait BlockCipher {

  def encrypt(key: SecretKey, msg: Array[Byte]): Try[Ciphertext]

  def decrypt(key: SecretKey, ciphertext: Ciphertext): Try[Array[Byte]]

  /*
  * Generates random AES key
  */
  def generateKey: SecretKey

  /*
  * Generates AES key from seed. The same seed generates the same key.
  */
  def generateKey(seed: Array[Byte]): SecretKey

  def keySize: Int
}

object BlockCipher {

  trait Ciphertext extends BytesSerializable

  trait SecretKey extends BytesSerializable
}
