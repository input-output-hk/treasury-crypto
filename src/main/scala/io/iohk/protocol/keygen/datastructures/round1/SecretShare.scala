package io.iohk.protocol.keygen.datastructures.round1

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.hybrid.dlp.{DLPHybridCiphertext, DLPHybridCiphertextSerializer}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize

import scala.util.Try

case class SecretShare(receiverID: Int, S: DLPHybridCiphertext)
  extends HasSize with BytesSerializable {

  override type M = SecretShare
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = SecretShareSerializer

  def size: Int = bytes.length
}

object SecretShareSerializer extends Serializer[SecretShare, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: SecretShare): Array[Byte] = {

    val S_bytes = obj.S.bytes

    Bytes.concat(
      Ints.toByteArray(obj.receiverID),
      Ints.toByteArray(S_bytes.length),
      S_bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)]): Try[SecretShare] = Try {
    val receiverID = Ints.fromByteArray(bytes.slice(0, 4))

    val S_bytes_len = Ints.fromByteArray(bytes.slice(4, 8))
    val S_bytes = bytes.slice(8, 8 + S_bytes_len)

    val S = DLPHybridCiphertextSerializer.parseBytes(S_bytes, decoder)

    SecretShare(receiverID, S.get)
  }
}