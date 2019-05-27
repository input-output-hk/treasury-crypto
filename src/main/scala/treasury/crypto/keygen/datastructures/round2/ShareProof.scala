package treasury.crypto.keygen.datastructures.round2

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.core._
import treasury.crypto.core.encryption.hybrid.{HybridCiphertext, HybridCiphertextSerializer}
import treasury.crypto.core.primitives.blockcipher.BlockCipher
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.keygen.IntAccumulator
import treasury.crypto.nizk.{ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

import scala.util.Try

case class ShareProof(
                       encryptedShare:  HybridCiphertext,
                       decryptedShare:  HybridPlaintext,
                       NIZKProof:       ElgamalDecrNIZKProof
                     )
  extends HasSize with BytesSerializable {

  override type M = ShareProof
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = ShareProofSerializer

  def size: Int = bytes.length
}

object ShareProofSerializer extends Serializer[ShareProof, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: ShareProof): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.encryptedShare.size),
      obj.encryptedShare.bytes,
      Ints.toByteArray(obj.decryptedShare.size),
      obj.decryptedShare.bytes,
      Ints.toByteArray(obj.NIZKProof.size),
      obj.NIZKProof.bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], csOpt: Option[(DiscreteLogGroup, BlockCipher)]): Try[ShareProof] = Try {
    val cs = csOpt.get
    val offset = IntAccumulator(0)

    val encryptedShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val encryptedShareBytes = bytes.slice(offset.value, offset.plus(encryptedShareBytesLen))

    val decryptedShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val decryptedShareBytes = bytes.slice(offset.value, offset.plus(decryptedShareBytesLen))

    val NIZKProofLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val NIZKProofBytes = bytes.slice(offset.value, offset.plus(NIZKProofLen))

    ShareProof(
      HybridCiphertextSerializer.parseBytes(encryptedShareBytes, Option(cs)).get,
      HybridPlaintextSerializer.parseBytes(decryptedShareBytes, Option(cs._1)).get,
      ElgamalDecrNIZKProofSerializer.parseBytes(NIZKProofBytes, Option(cs._1)).get
    )
  }
}
