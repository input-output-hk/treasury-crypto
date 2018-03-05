package treasury.crypto.keygen.datastructures.round4

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

case class OpenedShare(receiverID: Integer, S: HybridPlaintext)
  extends HasSize with BytesSerializable {

  override type M = OpenedShare
  override val serializer: Serializer[M] = OpenedShareSerializer

  def size: Int = bytes.length
}

object OpenedShareSerializer extends Serializer[OpenedShare] {

  override def toBytes(obj: OpenedShare): Array[Byte] = {

    val S_bytes = obj.S.bytes

    Bytes.concat(
      Ints.toByteArray(obj.receiverID),
      Ints.toByteArray(S_bytes.length),
      S_bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[OpenedShare] = Try {

    val offset = IntAccumulator(0)

    val receiverID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val S_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val S_bytes = bytes.slice(offset.value, offset.plus(S_bytes_len))

    val S = HybridPlaintextSerializer.parseBytes(S_bytes, cs)

    OpenedShare(receiverID, S.get)
  }
}