package io.iohk.core.crypto.encryption.hybrid.dlp

import com.google.common.primitives.{Bytes, Shorts}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class DLPHybridCiphertext(C1: GroupElement, encryptedMessage: BlockCipher.Ciphertext)
  extends BytesSerializable {

  override type M = DLPHybridCiphertext
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = DLPHybridCiphertextSerializer

  def size: Int = bytes.length
}

object DLPHybridCiphertextSerializer extends Serializer[DLPHybridCiphertext, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: DLPHybridCiphertext): Array[Byte] = {
    val c1Bytes = obj.C1.bytes
    val ciphertextBytes = obj.encryptedMessage.bytes
    assert(ciphertextBytes.length < Short.MaxValue)

    Bytes.concat(
      Array(c1Bytes.length.toByte), c1Bytes,
      Shorts.toByteArray(ciphertextBytes.length.toShort), ciphertextBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)]): Try[DLPHybridCiphertext] = Try {
      val c1Len = bytes(0)
      val c1Bytes = bytes.slice(1, c1Len + 1)
      val ciphertextLen = Shorts.fromByteArray(bytes.slice(c1Len + 1, c1Len + 1 + Shorts.BYTES))
      val ciphertextBytes = bytes.slice(c1Len + 1 + Shorts.BYTES, c1Len + 1 + Shorts.BYTES + ciphertextLen)

      val (group, cipher) = decoder.get
      val C1 = group.reconstructGroupElement(c1Bytes).get
      val ciphertext = cipher.reconstructCiphertextFromBytes(ciphertextBytes).get

      DLPHybridCiphertext(C1, ciphertext)
  }
}