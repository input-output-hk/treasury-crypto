package io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceSecretKeyLight, RnceSecretKeyLightSerializer}

import scala.util.Try

case class RnceBatchedSecretKey(secretKeys: Seq[RnceSecretKeyLight])
  extends BytesSerializable {

  override type M = RnceBatchedSecretKey
  override type DECODER = Unit
  override val serializer: Serializer[M, DECODER] = RnceBatchedSecretKeySerializer

  def size: Int = bytes.length
}

object RnceBatchedSecretKeySerializer extends Serializer[RnceBatchedSecretKey, Unit]{

  override def toBytes(obj: RnceBatchedSecretKey): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.secretKeys.length),
      obj.secretKeys.foldLeft(Array[Byte]()){
        (acc, sk) =>
          val sk_bytes = sk.bytes
          Bytes.concat(acc,
            Ints.toByteArray(sk_bytes.length),
            sk_bytes)
      }
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[Unit] = None): Try[RnceBatchedSecretKey] = Try{
    val basic_offset = Ints.BYTES
    val cts_num = Ints.fromByteArray(bytes.slice(0, basic_offset))

    RnceBatchedSecretKey(
      Array.range(0, cts_num).foldLeft((Array[RnceSecretKeyLight](), basic_offset)){
        (acc, _) =>
          val (sk, offset) = acc
          val sk_bytes_offset = offset + Ints.BYTES
          val sk_bytes_len = Ints.fromByteArray(bytes.slice(offset, sk_bytes_offset))
          val sk_bytes = bytes.slice(sk_bytes_offset, sk_bytes_offset + sk_bytes_len)
          (sk ++ Array(RnceSecretKeyLightSerializer.parseBytes(sk_bytes).get),
            offset + (Ints.BYTES + sk_bytes_len))
      }._1
    )
  }
}
