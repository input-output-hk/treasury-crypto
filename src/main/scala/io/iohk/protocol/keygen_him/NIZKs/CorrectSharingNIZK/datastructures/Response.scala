package io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.utils.BigIntSerializer
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

case class Response(Z1: Seq[BigInt], Z2: BigInt, Z3: Seq[BigInt])
  extends BytesSerializable {
  override type M = Response
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ResponseSerializer
}

object ResponseSerializer extends Serializer[Response, DiscreteLogGroup]{

  def toBytes(obj: Response): Array[Byte] = {
    val Z1_bytes = serializeSeq(obj.Z1, BigIntSerializer)
    val Z2_bytes = obj.Z2.toByteArray
    val Z3_bytes = serializeSeq(obj.Z3, BigIntSerializer)
    Bytes.concat(
      Z1_bytes,
      Ints.toByteArray(Z2_bytes.length), Z2_bytes,
      Z3_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Response] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val (z1, z2_size_offset) = parseSeq(
      bytes.slice(0, bytes.length),
      BigIntSerializer
    ).get

    val z2_offset = z2_size_offset + Ints.BYTES
    val z2_size = Ints.fromByteArray(bytes.slice(z2_size_offset, z2_offset))
    val z3_offset = z2_offset + z2_size

    val z2 = BigIntSerializer.parseBytes(bytes.slice(z2_offset, z3_offset)).get

    val z3 = parseSeq(
      bytes.slice(z3_offset, bytes.length),
      BigIntSerializer
    ).get._1

    Response(z1, z2, z3)
  }
}
