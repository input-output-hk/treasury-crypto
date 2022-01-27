package io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.utils.GroupElementSerializer

import scala.util.Try

case class Commitment(A: GroupElement, B: GroupElement, E: GroupElement, F: GroupElement)
  extends BytesSerializable {
  override type M = Commitment
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = CommitmentSerializer
}

object CommitmentSerializer extends Serializer[Commitment, DiscreteLogGroup]{
  def toBytes(obj: Commitment): Array[Byte] = {
    val A_bytes = obj.A.bytes
    val B_bytes = obj.B.bytes
    val E_bytes = obj.E.bytes
    val F_bytes = obj.F.bytes

    Bytes.concat(
      Ints.toByteArray(A_bytes.length), A_bytes,
      Ints.toByteArray(B_bytes.length), B_bytes,
      Ints.toByteArray(E_bytes.length), E_bytes,
      Ints.toByteArray(F_bytes.length), F_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Commitment] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    var offset = 0

    def readGroupElement: GroupElement = {
      val size = Ints.fromByteArray(bytes.slice(offset, offset + Ints.BYTES))
      offset = offset + Ints.BYTES

      val groupElement = GroupElementSerializer.parseBytes(
        bytes.slice(offset, offset + size),
        Some(group)
      ).get
      offset = offset + size
      groupElement
    }

    Commitment(
      readGroupElement,
      readGroupElement,
      readGroupElement,
      readGroupElement
    )
  }
}
