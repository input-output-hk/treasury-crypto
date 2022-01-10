package io.iohk.protocol.keygen_him.datastructures.R3Data

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.keygen_him.NIZKs.CorrectDecryptionNIZK.datastructures.{Proof, ProofSerializer}

import scala.util.Try

case class Complaint(share: DealersShare, proof: Proof)
  extends BytesSerializable {
  override type M = Complaint
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ComplaintSerializer

  def isValid: Boolean = { true }
}

object ComplaintSerializer extends Serializer[Complaint, DiscreteLogGroup]{
  def toBytes(obj: Complaint): Array[Byte] = {
    val share_bytes = obj.share.bytes
    val proof_bytes = obj.proof.bytes

    Bytes.concat(
      Ints.toByteArray(share_bytes.length),
      share_bytes,
      proof_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Complaint] = Try{
    val share_bytes_len = Ints.fromByteArray(bytes.slice(0, 4))
    val proof_offset = 4 + share_bytes_len

    val share_bytes = bytes.slice(4, proof_offset)
    val proof_bytes = bytes.slice(proof_offset, bytes.length)

    Complaint(
      DealersShareSerializer.parseBytes(share_bytes).get,
      ProofSerializer.parseBytes(proof_bytes, decoder).get
    )
  }
}
