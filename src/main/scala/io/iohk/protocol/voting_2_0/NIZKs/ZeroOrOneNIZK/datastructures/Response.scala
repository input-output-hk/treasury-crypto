package io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.utils.BigIntSerializer
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

case class Response(Z1: BigInt, z2: Seq[BigInt], Z3: BigInt)
  extends BytesSerializable {
  override type M = Response
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ResponseSerializer
}

object ResponseSerializer extends Serializer[Response, DiscreteLogGroup]{

  def toBytes(obj: Response): Array[Byte] = {
    val Z1_bytes = obj.Z1.toByteArray
    val Z2_bytes = serializeSeq(obj.z2, BigIntSerializer)
    val Z3_bytes = obj.Z3.toByteArray

    Bytes.concat(
      Ints.toByteArray(Z1_bytes.length), Z1_bytes,
      Z2_bytes,
      // no need to save Z3's length - just read it till the end of serialized bytes
      Z3_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Response] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val z1_size = Ints.fromByteArray(bytes.slice(0, Ints.BYTES))
    val z2_offset = Ints.BYTES + z1_size
    val z1 = BigIntSerializer.parseBytes(bytes.slice(Ints.BYTES, z2_offset)).get

    val (z2, z3_size_offset) = parseSeq(
      bytes.slice(z2_offset, bytes.length),
      BigIntSerializer
    ).get

    val z3 = BigIntSerializer.parseBytes(bytes.slice(z2_offset + z3_size_offset, bytes.length)).get

    Response(z1, z2, z3)
  }
}
