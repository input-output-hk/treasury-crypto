package io.iohk.keygen.datastructures.round4

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core._
import io.iohk.core.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class OpenedShare(receiverID: Integer, S: HybridPlaintext)
  extends HasSize with BytesSerializable {

  override type M = OpenedShare
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = OpenedShareSerializer

  def size: Int = bytes.length
}

object OpenedShareSerializer extends Serializer[OpenedShare, DiscreteLogGroup] {

  override def toBytes(obj: OpenedShare): Array[Byte] = {

    val S_bytes = obj.S.bytes

    Bytes.concat(
      Ints.toByteArray(obj.receiverID),
      Ints.toByteArray(S_bytes.length),
      S_bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], csOpt: Option[DiscreteLogGroup]): Try[OpenedShare] = Try {
    case class IntAccumulator(var value: Int = 0){
      def plus(i: Int): Int = {value += i; value}
    }

    val cs = csOpt.get
    val offset = IntAccumulator(0)

    val receiverID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val S_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val S_bytes = bytes.slice(offset.value, offset.plus(S_bytes_len))

    val S = HybridPlaintextSerializer.parseBytes(S_bytes, Option(cs))

    OpenedShare(receiverID, S.get)
  }
}