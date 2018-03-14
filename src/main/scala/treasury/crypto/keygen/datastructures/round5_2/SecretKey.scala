package treasury.crypto.keygen.datastructures.round5_2

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.core.{Cryptosystem, HasSize}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

case class SecretKey(
                      ownerID:   Integer,
                      secretKey: Array[Byte]
                    )
  extends HasSize with BytesSerializable {

  override type M = SecretKey
  override val serializer: Serializer[M] = SecretKeySerializer

  def size: Int = bytes.length
}

object SecretKeySerializer extends Serializer[SecretKey] {

  override def toBytes(obj: SecretKey): Array[Byte] = {

    Bytes.concat(
      Ints.toByteArray(obj.ownerID),
      Ints.toByteArray(obj.secretKey.length),
      obj.secretKey
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[SecretKey] = Try {

    val offset = IntAccumulator(0)

    val ownerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val secretKeyLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val secretKey = bytes.slice(offset.value, offset.plus(secretKeyLen))

    SecretKey(ownerID, secretKey)
  }
}