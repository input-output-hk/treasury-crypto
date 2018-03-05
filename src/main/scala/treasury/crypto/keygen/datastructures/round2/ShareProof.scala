package treasury.crypto.keygen.datastructures.round2

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.core._
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
  override val serializer: Serializer[M] = ShareProofSerializer

  def size: Int = bytes.length
}

object ShareProofSerializer extends Serializer[ShareProof] {

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

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[ShareProof] = Try {

    val offset = IntAccumulator(0)

    val encryptedShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val encryptedShareBytes = bytes.slice(offset.value, offset.plus(encryptedShareBytesLen))

    val decryptedShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val decryptedShareBytes = bytes.slice(offset.value, offset.plus(decryptedShareBytesLen))

    val NIZKProofLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val NIZKProofBytes = bytes.slice(offset.value, offset.plus(NIZKProofLen))

    ShareProof(
      HybridCiphertextSerializer.parseBytes(encryptedShareBytes, cs).get,
      HybridPlaintextSerializer.parseBytes(decryptedShareBytes, cs).get,
      ElgamalDecrNIZKProofSerializer.parseBytes(NIZKProofBytes, cs).get
    )
  }
}
