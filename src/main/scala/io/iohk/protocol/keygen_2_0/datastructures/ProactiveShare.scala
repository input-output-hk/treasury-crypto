package io.iohk.protocol.keygen_2_0.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.datastructures.{Share, ShareSerializer}

import scala.util.Try

case class ProactiveShare(dealerPoint: Int = 0, f_share: Share) extends BytesSerializable {
  override type M = ProactiveShare
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = ProactiveShareSerializer
}

object ProactiveShareSerializer extends Serializer[ProactiveShare, (DiscreteLogGroup, BlockCipher)] {

  def toBytes(obj: ProactiveShare): Array[Byte] = {

    val f_share_bytes = obj.f_share.bytes

    Bytes.concat(
      Ints.toByteArray(obj.dealerPoint),
      Ints.toByteArray(f_share_bytes.length),
      f_share_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)] = None): Try[ProactiveShare] = Try {
    val dealerPoint = Ints.fromByteArray(bytes.slice(0, 4))
    val f_share_bytes_len = Ints.fromByteArray(bytes.slice(4, 8))
    val f_share_bytes = bytes.slice(8, 8 + f_share_bytes_len)

    val f_share = ShareSerializer.parseBytes(f_share_bytes)

    ProactiveShare(dealerPoint, f_share.get)
  }
}
