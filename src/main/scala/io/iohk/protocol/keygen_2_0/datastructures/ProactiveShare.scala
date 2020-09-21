package io.iohk.protocol.keygen_2_0.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class ProactiveShare(dealerPoint: Int = 0, f_point: Int, g_share: Share) extends BytesSerializable {
  override type M = ProactiveShare
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = ProactiveShareSerializer
}

object ProactiveShareSerializer extends Serializer[ProactiveShare, (DiscreteLogGroup, BlockCipher)] {

  def toBytes(obj: ProactiveShare): Array[Byte] = {

    val g_share_bytes = obj.g_share.bytes

    Bytes.concat(
      Ints.toByteArray(obj.dealerPoint),
      Ints.toByteArray(obj.f_point),
      Ints.toByteArray(g_share_bytes.length),
      g_share_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)] = None): Try[ProactiveShare] = Try {
    val dealerId = Ints.fromByteArray(bytes.slice(0, 4))
    val f_point = Ints.fromByteArray(bytes.slice(4, 8))

    val g_share_bytes_len = Ints.fromByteArray(bytes.slice(8, 12))
    val g_share_bytes = bytes.slice(12, 12 + g_share_bytes_len)

    val g_share = ShareSerializer.parseBytes(g_share_bytes)

    ProactiveShare(dealerId, f_point, g_share.get)
  }
}
