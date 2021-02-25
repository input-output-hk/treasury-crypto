package io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.keygen_2_0.utils.DlogGroupArithmetics.{exp, mul}

import scala.util.Try

case class RncePublicKeyLight(h: GroupElement)
  extends BytesSerializable {

  override type M = RncePublicKeyLight
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = RncePublicKeyLightSerializer

  def size: Int = bytes.length
}

object RncePublicKeyLight{
  def create(x1: BigInt, x2: BigInt, crs: RnceCrsLight)(implicit group: DiscreteLogGroup): RncePublicKeyLight = {
    RncePublicKeyLight(mul(exp(crs.g1, x1), exp(crs.g2, x2)))
  }
}

object RncePublicKeyLightSerializer extends Serializer[RncePublicKeyLight, DiscreteLogGroup]{

  override def toBytes(obj: RncePublicKeyLight): Array[Byte] = {
    val hBytes = obj.h.bytes

    Bytes.concat(
      Array(hBytes.length.toByte), hBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[RncePublicKeyLight] = Try{
    val hLen = bytes(0)
    val hBytes = bytes.slice(1, 1 + hLen)

    RncePublicKeyLight(
      decoder.get.reconstructGroupElement(hBytes).get
    )
  }
}
