package io.iohk.protocol.keygen.datastructures.round5_2

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.Cryptosystem
import io.iohk.protocol.keygen.IntAccumulator

import scala.util.Try

case class SecretKey(
                      ownerID:   Integer,
                      secretKey: Array[Byte]
                    )
  extends HasSize with BytesSerializable {

  override type M = SecretKey
  override type DECODER = Cryptosystem
  override val serializer: Serializer[M, DECODER] = SecretKeySerializer

  def size: Int = bytes.length
}

object SecretKeySerializer extends Serializer[SecretKey, Cryptosystem] {

  override def toBytes(obj: SecretKey): Array[Byte] = {

    Bytes.concat(
      Ints.toByteArray(obj.ownerID),
      Ints.toByteArray(obj.secretKey.length),
      obj.secretKey
    )
  }

  override def parseBytes(bytes: Array[Byte], csOpt: Option[Cryptosystem]): Try[SecretKey] = Try {

    val offset = IntAccumulator(0)

    val ownerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val secretKeyLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val secretKey = bytes.slice(offset.value, offset.plus(secretKeyLen))

    SecretKey(ownerID, secretKey)
  }
}