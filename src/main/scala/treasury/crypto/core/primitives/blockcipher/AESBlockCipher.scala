package treasury.crypto.core.primitives.blockcipher

import treasury.crypto.core.primitives.blockcipher.BlockCipher.{Ciphertext, SecretKey}
import treasury.crypto.core.serialization.{NODECODER, Serializer}

import scala.util.Try

trait AESBlockCipher extends BlockCipher {

  override def reconstructCiphertextFromBytes(bytes: Array[Byte]): Try[BlockCipher.Ciphertext] = Try {
    AESCiphertext(bytes)
  }

  override def reconstructSecretKeyFromBytes(bytes: Array[Byte]): Try[SecretKey] = Try {
    require(bytes.length == keySize)
    AESSecretKey(bytes)
  }
}

trait AES128 extends AESBlockCipher
trait AES128_GSM extends AES128

trait AES192 extends AESBlockCipher

trait AES256 extends AESBlockCipher


case class AESCiphertext(ciphertext: Array[Byte]) extends Ciphertext {
  override type M = AESCiphertext
  override type DECODER = NODECODER
  override def serializer: Serializer[M, DECODER] = AESCiphertextSerializer
}

object AESCiphertextSerializer extends Serializer[AESCiphertext, NODECODER] {
  override def toBytes(obj: AESCiphertext): Array[Byte] = obj.ciphertext
  override def parseBytes(bytes: Array[Byte], d: Option[NODECODER] = None): Try[AESCiphertext] = Try(AESCiphertext(bytes))
}

case class AESSecretKey(key: Array[Byte]) extends SecretKey {
  override type M = AESSecretKey
  override type DECODER = NODECODER
  override def serializer: Serializer[M, DECODER] = AESSecretKeySerializer
}

object AESSecretKeySerializer extends Serializer[AESSecretKey, NODECODER] {
  override def toBytes(obj: AESSecretKey): Array[Byte] = obj.key
  override def parseBytes(bytes: Array[Byte], d: Option[NODECODER] = None): Try[AESSecretKey] = Try(AESSecretKey(bytes))
}
