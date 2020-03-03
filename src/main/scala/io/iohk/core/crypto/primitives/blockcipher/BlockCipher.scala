package io.iohk.core.crypto.primitives.blockcipher

import io.iohk.core.crypto.primitives.blockcipher.BlockCipher.{Ciphertext, SecretKey}
import io.iohk.core.serialization.BytesSerializable

import scala.util.Try

trait BlockCipher {

  def encrypt(key: SecretKey, msg: Array[Byte]): Try[Ciphertext]

  def decrypt(key: SecretKey, ciphertext: Ciphertext): Try[Array[Byte]]

  /**
    * Generates random AES key
    */
  def generateKey: SecretKey

  /**
    * Generates AES key from seed. The same seed generates the same key.
    */
  def generateKey(seed: Array[Byte]): SecretKey

  /**
    * Deserialize ciphertext from bytes into appropriate Ciphertext instance
    */
  def reconstructCiphertextFromBytes(bytes: Array[Byte]): Try[Ciphertext]

  /**
    * Deserialize secret key from bytes into appropriate SecretKey instance
    */
  def reconstructSecretKeyFromBytes(bytes: Array[Byte]): Try[SecretKey]

  def keySize: Int
}

object BlockCipher {

  trait Ciphertext extends BytesSerializable

  trait SecretKey extends BytesSerializable
}
