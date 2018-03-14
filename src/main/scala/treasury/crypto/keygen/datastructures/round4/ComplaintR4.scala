package treasury.crypto.keygen.datastructures.round4

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.{Cryptosystem, HasSize}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

case class ComplaintR4(
                        violatorID:  Integer,
                        share_a:     OpenedShare,
                        share_b:     OpenedShare
                      )
  extends HasSize with BytesSerializable {

  override type M = ComplaintR4
  override val serializer: Serializer[M] = ComplaintR4Serializer

  def size: Int = bytes.length
}

object ComplaintR4Serializer extends Serializer[ComplaintR4] {

  override def toBytes(obj: ComplaintR4): Array[Byte] = {

    Bytes.concat(
      Ints.toByteArray(obj.violatorID),
      Ints.toByteArray(obj.share_a.size),
      obj.share_a.bytes,
      Ints.toByteArray(obj.share_b.size),
      obj.share_b.bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[ComplaintR4] = Try {

    val offset = IntAccumulator(0)

    val violatorID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val share_a_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val share_a_Bytes = bytes.slice(offset.value, offset.plus(share_a_len))

    val share_b_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val share_b_Bytes = bytes.slice(offset.value, offset.plus(share_b_len))

    ComplaintR4(
      violatorID,
      OpenedShareSerializer.parseBytes(share_a_Bytes, cs).get,
      OpenedShareSerializer.parseBytes(share_b_Bytes, cs).get)
  }
}