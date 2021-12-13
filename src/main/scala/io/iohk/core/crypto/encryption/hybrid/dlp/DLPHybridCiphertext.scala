package io.iohk.core.crypto.encryption.hybrid.dlp

import com.google.common.primitives.{Bytes, Shorts}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class DLPHybridCiphertext(encryptedKey: GroupElement, encryptedMessage: BlockCipher.Ciphertext)
  extends BytesSerializable {

  override type M = DLPHybridCiphertext
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = DLPHybridCiphertextSerializer

  def size: Int = bytes.length
}

object DLPHybridCiphertextSerializer extends Serializer[DLPHybridCiphertext, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: DLPHybridCiphertext): Array[Byte] = {
    val keyBytes = obj.encryptedKey.bytes
    val ciphertextBytes = obj.encryptedMessage.bytes
    assert(ciphertextBytes.length < Short.MaxValue)

    Bytes.concat(
      Array(keyBytes.length.toByte), keyBytes,
      Shorts.toByteArray(ciphertextBytes.length.toShort), ciphertextBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)]): Try[DLPHybridCiphertext] = Try {
      val keyLen = bytes(0)
      val keyBytes = bytes.slice(1, keyLen + 1)
      val ciphertextLen = Shorts.fromByteArray(bytes.slice(keyLen + 1, keyLen + 1 + Shorts.BYTES))
      val ciphertextBytes = bytes.slice(keyLen + 1 + Shorts.BYTES, keyLen + 1 + Shorts.BYTES + ciphertextLen)

      val (group, cipher) = decoder.get
      val key = group.reconstructGroupElement(keyBytes).get
      val ciphertext = cipher.reconstructCiphertextFromBytes(ciphertextBytes).get

      DLPHybridCiphertext(key, ciphertext)
  }
}