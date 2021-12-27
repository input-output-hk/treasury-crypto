package io.iohk.protocol.common.dlog_encryption

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize

import scala.util.Try

case class DLogCiphertext(C: Seq[ElGamalCiphertext]) extends HasSize with BytesSerializable {

  override type M = DLogCiphertext
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = DLogCiphertextSerializer

  def size: Int = bytes.length
}

object DLogCiphertextSerializer extends Serializer[DLogCiphertext, DiscreteLogGroup] {
  override def toBytes(obj: DLogCiphertext): Array[Byte] = {
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

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[DLogCiphertext] = Try {
    val basic_offset = Ints.BYTES
    val cts_num = Ints.fromByteArray(bytes.slice(0, basic_offset))

    DLogCiphertext(
      Array.range(0, cts_num).foldLeft((Array[ElGamalCiphertext](), basic_offset)){
        (acc, _) =>
          val (c, offset) = acc
          val c_bytes_offset = offset + Ints.BYTES
          val c_bytes_len = Ints.fromByteArray(bytes.slice(offset, c_bytes_offset))
          val c_bytes = bytes.slice(c_bytes_offset, c_bytes_offset + c_bytes_len)
          (c ++ Array(ElGamalCiphertextSerializer.parseBytes(c_bytes, decoder).get),
            offset + (4 + c_bytes_len))
      }._1
    )
  }
}
