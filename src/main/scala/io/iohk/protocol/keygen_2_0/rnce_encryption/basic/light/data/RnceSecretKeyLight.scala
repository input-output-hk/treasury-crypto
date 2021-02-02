package io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data

import com.google.common.primitives.Bytes
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class RnceSecretKeyLight(x1: BigInt,
                              x2: BigInt)

  extends BytesSerializable {

  override type M = RnceSecretKeyLight
  override type DECODER = Unit
  override val serializer: Serializer[M, DECODER] = RnceSecretKeyLightSerializer

  def size: Int = bytes.length
}

object RnceSecretKeyLightSerializer extends Serializer[RnceSecretKeyLight, Unit]{

  override def toBytes(obj: RnceSecretKeyLight): Array[Byte] = {
    val x1Bytes = obj.x1.toByteArray
    val x2Bytes = obj.x2.toByteArray

    Bytes.concat(
      Array(x1Bytes.length.toByte), x1Bytes,
      Array(x2Bytes.length.toByte), x2Bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[Unit] = None): Try[RnceSecretKeyLight] = Try{
    var offset = 0
    def offsetPlus(n: Int): Int = {offset = offset + n; offset}

    val x1Len = bytes(offset)
    val x1Bytes = bytes.slice(offsetPlus(1), offsetPlus(x1Len))

    val x2Len = bytes(offset)
    val x2Bytes = bytes.slice(offsetPlus(1), offsetPlus(x2Len))

    RnceSecretKeyLight(
      BigInt(x1Bytes),
      BigInt(x2Bytes)
    )
  }
}

//-----------------------------------------------------------
// Template for serializer implementation
//-----------------------------------------------------------
//  extends BytesSerializable {
//
//  override type M = SerializedType
//  override type DECODER = DiscreteLogGroup
//  override val serializer: Serializer[M, DECODER] = SerializedTypeSerializer
//
//  def size: Int = bytes.length
//}
//
//object SerializedTypeSerializer extends Serializer[SerializedType, DiscreteLogGroup]{
//
//  override def toBytes(obj: SerializedType): Array[Byte] = {
//
//  }
//
//  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[SerializedType] = Try{
//
//  }
//}
