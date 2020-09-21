package io.iohk.protocol.keygen_2_0.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class Share(point: Int, value: BigInt) extends BytesSerializable {
  override type M = Share
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = ShareSerializer
}

object ShareSerializer extends Serializer[Share, (DiscreteLogGroup, BlockCipher)] {

  def toBytes(obj: Share): Array[Byte] = {

    val value_bytes = obj.value.toByteArray

    Bytes.concat(
      Ints.toByteArray(obj.point),
      Ints.toByteArray(value_bytes.length),
      value_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)] = None): Try[Share] = Try {
    val point = Ints.fromByteArray(bytes.slice(0, 4))

    val value_bytes_len = Ints.fromByteArray(bytes.slice(4, 8))
    val value_bytes = bytes.slice(8, 8 + value_bytes_len)

    val value = BigInt(value_bytes)

    Share(point, value)
  }
}
