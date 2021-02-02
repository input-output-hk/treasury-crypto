package io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.keygen_2_0.dlog_encryption.DLogCiphertext
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCiphertextLight, RnceCiphertextLightSerializer}

import scala.util.Try

case class RnceBatchedCiphertext(C: Seq[RnceCiphertextLight])
  extends BytesSerializable {

  override type M = RnceBatchedCiphertext
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = RnceBatchedCiphertextSerializer

  def size: Int = bytes.length
}

object RnceBatchedCiphertextSerializer extends Serializer[RnceBatchedCiphertext, DiscreteLogGroup]{

  override def toBytes(obj: RnceBatchedCiphertext): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.C.length),
      obj.C.foldLeft(Array[Byte]()){
        (acc, c) =>
          val c_bytes = c.bytes
          Bytes.concat(acc,
            Ints.toByteArray(c_bytes.length),
            c_bytes)
      }
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[RnceBatchedCiphertext] = Try{
    val basic_offset = Ints.BYTES
    val cts_num = Ints.fromByteArray(bytes.slice(0, basic_offset))

    RnceBatchedCiphertext(
      Array.range(0, cts_num).foldLeft((Array[RnceCiphertextLight](), basic_offset)){
        (acc, _) =>
          val (c, offset) = acc
          val c_bytes_offset = offset + Ints.BYTES
          val c_bytes_len = Ints.fromByteArray(bytes.slice(offset, c_bytes_offset))
          val c_bytes = bytes.slice(c_bytes_offset, c_bytes_offset + c_bytes_len)
          (c ++ Array(RnceCiphertextLightSerializer.parseBytes(c_bytes, decoder).get),
            offset + (Ints.BYTES + c_bytes_len))
      }._1
    )
  }
}