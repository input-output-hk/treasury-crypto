package io.iohk.core.crypto.encryption.hybrid

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class HybridPlaintext(decryptedKey: GroupElement, decryptedMessage: Array[Byte])
  extends BytesSerializable {

  override type M = HybridPlaintext
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = HybridPlaintextSerializer

  def size: Int = bytes.length
}

object HybridPlaintextSerializer extends Serializer[HybridPlaintext, DiscreteLogGroup] {

  override def toBytes(obj: HybridPlaintext): Array[Byte] =
  {
    val decryptedKeyBytes = obj.decryptedKey.bytes

    Bytes.concat(
      Ints.toByteArray(decryptedKeyBytes.length),
      decryptedKeyBytes,
      Ints.toByteArray(obj.decryptedMessage.length),
      obj.decryptedMessage
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[HybridPlaintext] = Try {
    val group = decoder.get

    val decryptedKeyBytesLen = Ints.fromByteArray(bytes.slice(0, 4))
    val decryptedKeyBytes = bytes.slice(4, 4 + decryptedKeyBytesLen)

    val decryptedMessageLen = Ints.fromByteArray(bytes.slice(4 + decryptedKeyBytesLen, 8 + decryptedKeyBytesLen))
    val decryptedMessage = bytes.slice(8 + decryptedKeyBytesLen, 8 + decryptedKeyBytesLen + decryptedMessageLen)

    HybridPlaintext(
      group.reconstructGroupElement(decryptedKeyBytes).get,
      decryptedMessage
    )
  }
}
