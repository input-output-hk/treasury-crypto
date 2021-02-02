package io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RncePublicKeyLight, RncePublicKeyLightSerializer}

import scala.util.Try

case class RnceBatchedPubKey(pubKeys: Seq[RncePublicKeyLight])
  extends BytesSerializable {

  override type M = RnceBatchedPubKey
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = RnceBatchedPubKeySerializer

  def size: Int = bytes.length
  val firstPubKey: GroupElement = pubKeys.head.h
}

object RnceBatchedPubKeySerializer extends Serializer[RnceBatchedPubKey, DiscreteLogGroup]{

  override def toBytes(obj: RnceBatchedPubKey): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.pubKeys.length),
      obj.pubKeys.foldLeft(Array[Byte]()){
        (acc, pk) =>
          val pk_bytes = pk.bytes
          Bytes.concat(acc,
            Ints.toByteArray(pk_bytes.length),
            pk_bytes)
      }
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[RnceBatchedPubKey] = Try{
    val basic_offset = Ints.BYTES
    val cts_num = Ints.fromByteArray(bytes.slice(0, basic_offset))

    RnceBatchedPubKey(
      Array.range(0, cts_num).foldLeft((Array[RncePublicKeyLight](), basic_offset)){
        (acc, _) =>
          val (pk, offset) = acc
          val pk_bytes_offset = offset + Ints.BYTES
          val pk_bytes_len = Ints.fromByteArray(bytes.slice(offset, pk_bytes_offset))
          val pk_bytes = bytes.slice(pk_bytes_offset, pk_bytes_offset + pk_bytes_len)
          (pk ++ Array(RncePublicKeyLightSerializer.parseBytes(pk_bytes, decoder).get),
            offset + (Ints.BYTES + pk_bytes_len))
      }._1
    )
  }
}
