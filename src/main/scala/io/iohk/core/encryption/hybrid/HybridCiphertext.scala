package io.iohk.core.encryption.hybrid

import com.google.common.primitives.{Bytes, Shorts}
import io.iohk.core.encryption.elgamal.ElGamalCiphertextSerializer
import io.iohk.core.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.primitives.blockcipher.BlockCipher
import io.iohk.core.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class HybridCiphertext(encryptedSymmetricKey: ElGamalCiphertext, encryptedMessage: BlockCipher.Ciphertext)
  extends BytesSerializable {

  override type M = HybridCiphertext
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = HybridCiphertextSerializer

  def size: Int = bytes.length
}

object HybridCiphertextSerializer extends Serializer[HybridCiphertext, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: HybridCiphertext): Array[Byte] = {
    val keyBytes = obj.encryptedSymmetricKey.bytes
    val ciphertextBytes = obj.encryptedMessage.bytes
    assert(ciphertextBytes.length < Short.MaxValue)

    Bytes.concat(
      Array(keyBytes.length.toByte), keyBytes,
      Shorts.toByteArray(ciphertextBytes.length.toShort), ciphertextBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)]): Try[HybridCiphertext] = Try {
      val keyLen = bytes(0)
      val keyBytes = bytes.slice(1, keyLen + 1)
      val ciphertextLen = Shorts.fromByteArray(bytes.slice(keyLen + 1, keyLen + 1 + Shorts.BYTES))
      val ciphertextBytes = bytes.slice(keyLen + 1 + Shorts.BYTES, keyLen + 1 + Shorts.BYTES + ciphertextLen)

      val (group, cipher) = decoder.get
      val key = ElGamalCiphertextSerializer.parseBytes(keyBytes, Option(group)).get
      val ciphertext = cipher.reconstructCiphertextFromBytes(ciphertextBytes).get

      HybridCiphertext(key, ciphertext)
  }
}