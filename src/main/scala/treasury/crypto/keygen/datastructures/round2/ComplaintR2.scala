package treasury.crypto.keygen.datastructures.round2

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.core.{Cryptosystem, HasSize, PubKey}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

case class ComplaintR2(
                        violatorID:        Integer,
                        issuerPublicKey:   PubKey,
                        shareProof_a:      ShareProof,
                        shareProof_b:      ShareProof
                      )
  extends HasSize  with BytesSerializable {

  override type M = ComplaintR2
  override val serializer: Serializer[M] = ComplaintR2Serializer

  def size: Int = bytes.length
}

object ComplaintR2Serializer extends Serializer[ComplaintR2] {

  override def toBytes(obj: ComplaintR2): Array[Byte] = {

    val issuerPublicKeyBytes = obj.issuerPublicKey.getEncoded(true)

    Bytes.concat(
      Ints.toByteArray(obj.violatorID),
      Ints.toByteArray(issuerPublicKeyBytes.length),
      issuerPublicKeyBytes,
      Ints.toByteArray(obj.shareProof_a.size),
      obj.shareProof_a.bytes,
      Ints.toByteArray(obj.shareProof_b.size),
      obj.shareProof_b.bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[ComplaintR2] = Try {

    val offset = IntAccumulator(0)

    val violatorID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val issuerPublicKeyByteslen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val issuerPublicKeyBytes = bytes.slice(offset.value, offset.plus(issuerPublicKeyByteslen))

    val shareProof_a_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val shareProof_a_Bytes = bytes.slice(offset.value, offset.plus(shareProof_a_len))

    val shareProof_b_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val shareProof_b_Bytes = bytes.slice(offset.value, offset.plus(shareProof_b_len))

    ComplaintR2(
      violatorID,
      cs.decodePoint(issuerPublicKeyBytes),
      ShareProofSerializer.parseBytes(shareProof_a_Bytes, cs).get,
      ShareProofSerializer.parseBytes(shareProof_b_Bytes, cs).get
    )
  }
}
