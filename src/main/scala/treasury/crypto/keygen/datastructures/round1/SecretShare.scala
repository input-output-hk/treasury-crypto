package treasury.crypto.keygen.datastructures.round1

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.encryption.hybrid.{HybridCiphertext, HybridCiphertextSerializer}
import treasury.crypto.core.primitives.blockcipher.BlockCipher
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.core.{Cryptosystem, HasSize}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

case class SecretShare(receiverID: Integer, S: HybridCiphertext)
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

  override def parseBytes(bytes: Array[Byte], csOpt: Option[(DiscreteLogGroup, BlockCipher)]): Try[SecretShare] = Try {
    val cs = csOpt.get
    val offset = IntAccumulator(0)

    val receiverID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val S_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val S_bytes = bytes.slice(offset.value, offset.plus(S_bytes_len))

    val S = HybridCiphertextSerializer.parseBytes(S_bytes, Option(cs))

    SecretShare(receiverID, S.get)
  }
}