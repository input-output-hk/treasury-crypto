package io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class RnceCiphertextLight(u1: GroupElement,
                               u2: GroupElement,
                               e: GroupElement)
  extends BytesSerializable {

  override type M = RnceCiphertextLight
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = RnceCiphertextLightSerializer

  def size: Int = bytes.length
}

object RnceCiphertextLightSerializer extends Serializer[RnceCiphertextLight, DiscreteLogGroup]{

  override def toBytes(obj: RnceCiphertextLight): Array[Byte] = {
    val u1Bytes = obj.u1.bytes
    val u2Bytes = obj.u2.bytes
    val eBytes  = obj.e.bytes

    Bytes.concat(
      Array(u1Bytes.length.toByte), u1Bytes,
      Array(u2Bytes.length.toByte), u2Bytes,
      Array(eBytes.length.toByte),  eBytes
    )
  }


  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[RnceCiphertextLight] = Try{
    var offset = 0
    def offsetPlus(n: Int): Int = {offset = offset + n; offset}

    val u1Len = bytes(offset)
    val u1Bytes = bytes.slice(offsetPlus(1), offsetPlus(u1Len))

    val u2Len = bytes(offset)
    val u2Bytes = bytes.slice(offsetPlus(1), offsetPlus(u2Len))

    val eLen = bytes(offset)
    val eBytes = bytes.slice(offsetPlus(1), offsetPlus(eLen))

    val group = decoder.get

    RnceCiphertextLight(
      group.reconstructGroupElement(u1Bytes).get,
      group.reconstructGroupElement(u2Bytes).get,
      group.reconstructGroupElement(eBytes).get
    )
  }
}