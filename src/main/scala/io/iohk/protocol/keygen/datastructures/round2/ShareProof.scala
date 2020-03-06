package io.iohk.protocol.keygen.datastructures.round2

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.hybrid.{HybridCiphertext, HybridCiphertextSerializer, HybridPlaintext, HybridPlaintextSerializer}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.nizk.{ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

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

  override def parseBytes(bytes: Array[Byte], ctxOpt: Option[(DiscreteLogGroup, BlockCipher)]): Try[ShareProof] = Try {
    case class IntAccumulator(var value: Int = 0){
      def plus(i: Int): Int = {value += i; value}
    }

    val ctx = ctxOpt.get
    val offset = IntAccumulator(0)

    val encryptedShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val encryptedShareBytes = bytes.slice(offset.value, offset.plus(encryptedShareBytesLen))

    val decryptedShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val decryptedShareBytes = bytes.slice(offset.value, offset.plus(decryptedShareBytesLen))

    val NIZKProofLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val NIZKProofBytes = bytes.slice(offset.value, offset.plus(NIZKProofLen))

    ShareProof(
      HybridCiphertextSerializer.parseBytes(encryptedShareBytes, Option(ctx)).get,
      HybridPlaintextSerializer.parseBytes(decryptedShareBytes, Option(ctx._1)).get,
      ElgamalDecrNIZKProofSerializer.parseBytes(NIZKProofBytes, Option(ctx._1)).get
    )
  }
}
