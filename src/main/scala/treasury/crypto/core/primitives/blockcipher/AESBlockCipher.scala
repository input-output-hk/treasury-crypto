package treasury.crypto.core.primitives.blockcipher

import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.primitives.blockcipher.BlockCipher.{Ciphertext, SecretKey}
import treasury.crypto.core.serialization.Serializer

import scala.util.Try

trait AESBlockCipher extends BlockCipher

trait AES128 extends AESBlockCipher
trait AES128_GSM extends AES128

trait AES192 extends AESBlockCipher

trait AES256 extends AESBlockCipher


case class AESCiphertext(ciphertext: Array[Byte]) extends Ciphertext {
  override type M = AESCiphertext
  override def serializer: Serializer[AESCiphertext] = AESCiphertextSerializer
}

object AESCiphertextSerializer extends Serializer[AESCiphertext] {
  override def toBytes(obj: AESCiphertext): Array[Byte] = obj.ciphertext
  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[AESCiphertext] = Try(AESCiphertext(bytes))
}

case class AESSecretKey(key: Array[Byte]) extends SecretKey {
  override type M = AESSecretKey
  override def serializer: Serializer[AESSecretKey] = AESSecretKeySerializer
}

object AESSecretKeySerializer extends Serializer[AESSecretKey] {
  override def toBytes(obj: AESSecretKey): Array[Byte] = obj.key
  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[AESSecretKey] = Try(AESSecretKey(bytes))
}
