package io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.utils.GroupElementSerializer
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

case class Commitment(A: GroupElement, B: Seq[GroupElement], C: GroupElement)
  extends BytesSerializable {
  override type M = Commitment
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = CommitmentSerializer
}

object CommitmentSerializer extends Serializer[Commitment, DiscreteLogGroup]{
  def toBytes(obj: Commitment): Array[Byte] = {
    val A_bytes = obj.A.bytes
    val B_bytes = serializeSeq(obj.B, GroupElementSerializer)
    val C_bytes = obj.C.bytes
    Bytes.concat(
      Ints.toByteArray(A_bytes.length),
      A_bytes,
      B_bytes,
      // no need to save C's length - just read it till the end of serialized bytes
      C_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Commitment] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val a_size = Ints.fromByteArray(bytes.slice(0, Ints.BYTES))
    val b_offset = Ints.BYTES + a_size

    val a = GroupElementSerializer.parseBytes(
      bytes.slice(Ints.BYTES, b_offset),
      Some(group)
    ).get

    val (b, c_offset) = parseSeq(
      bytes.slice(b_offset, bytes.length),
      GroupElementSerializer
    ).get

    val c = GroupElementSerializer.parseBytes(
      bytes.slice(b_offset + c_offset, bytes.length),
      Some(group)
    ).get

    Commitment(a, b, c)
  }
}
