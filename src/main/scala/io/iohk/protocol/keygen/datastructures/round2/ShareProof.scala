package io.iohk.protocol.keygen.datastructures.round2

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.hybrid.dlp.{DLPHybridCiphertext, DLPHybridCiphertextSerializer}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.nizk.{DLPHybridDecrNIZKProof, DLPHybridDecrNIZKProofSerializer}

import scala.util.Try

case class ShareProof(decryptedShare:  Array[Byte],
                      NIZKProof:       DLPHybridDecrNIZKProof)
  extends HasSize with BytesSerializable {

  override type M = ShareProof
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = ShareProofSerializer

  def size: Int = bytes.length
}

object ShareProofSerializer extends Serializer[ShareProof, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: ShareProof): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.decryptedShare.size),
      obj.decryptedShare,
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

    val decryptedShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val decryptedShareBytes = bytes.slice(offset.value, offset.plus(decryptedShareBytesLen))

    val NIZKProofLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val NIZKProofBytes = bytes.slice(offset.value, offset.plus(NIZKProofLen))

    ShareProof(
      decryptedShareBytes,
      DLPHybridDecrNIZKProofSerializer.parseBytes(NIZKProofBytes, Option(ctx._1)).get
    )
  }
}
