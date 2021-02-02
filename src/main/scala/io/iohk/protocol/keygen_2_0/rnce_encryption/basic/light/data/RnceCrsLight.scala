package io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class RnceCrsLight(g1: GroupElement,
                        g2: GroupElement)
  extends BytesSerializable {

  override type M = RnceCrsLight
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = RnceCrsLightSerializer

  def size: Int = bytes.length
}

object RnceCrsLightSerializer extends Serializer[RnceCrsLight, DiscreteLogGroup]{

  override def toBytes(obj: RnceCrsLight): Array[Byte] = {
    val g1Bytes = obj.g1.bytes
    val g2Bytes = obj.g2.bytes

    Bytes.concat(
      Array(g1Bytes.length.toByte), g1Bytes,
      Array(g2Bytes.length.toByte), g2Bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[RnceCrsLight] = Try{
    var offset = 0
    def offsetPlus(n: Int): Int = {offset = offset + n; offset}

    val g1Len = bytes(offset)
    val g1Bytes = bytes.slice(offsetPlus(1), offsetPlus(g1Len))

    val g2Len = bytes(offset)
    val g2Bytes = bytes.slice(offsetPlus(1), offsetPlus(g2Len))

    val group = decoder.get

    RnceCrsLight(
      group.reconstructGroupElement(g1Bytes).get,
      group.reconstructGroupElement(g2Bytes).get
    )
  }
}
