package io.iohk.protocol.keygen_him.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.datastructures.{SecretShare, SecretShareSerializer}
import io.iohk.protocol.common.utils.GroupElementSerializer
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}
import io.iohk.protocol.keygen_him.NIZKs.datastructures.{Proof, ProofSerializer}

import scala.util.Try

case class R1Data(senderID: Int,
                  encShares: Seq[SecretShare],
                  coeffsCommitments: Seq[GroupElement], // Pedersen commitments: g^a * h^r
                  proofNIZK: Proof)
  extends BytesSerializable {
  override type M = R1Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = R1DataSerializer
}

object R1DataSerializer extends Serializer[R1Data, DiscreteLogGroup]{

  def toBytes(obj: R1Data): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.senderID),
      serializeSeq(obj.encShares, SecretShareSerializer),
      serializeSeq(obj.coeffsCommitments, GroupElementSerializer),
      obj.proofNIZK.bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[R1Data] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val (senderID, encSharesOffset) = (Ints.fromByteArray(bytes.slice(0, Ints.BYTES)), Ints.BYTES)

    val (encShares, coeffsCommitmentsOffset) = parseSeq(
      bytes.slice(encSharesOffset, bytes.length),
      SecretShareSerializer
    ).get

    val (coeffsCommitments, proofOffset) = parseSeq(
      bytes.slice(encSharesOffset + coeffsCommitmentsOffset, bytes.length),
      GroupElementSerializer
    ).get

    val proof = ProofSerializer.parseBytes(
      bytes.slice(encSharesOffset + coeffsCommitmentsOffset + proofOffset, bytes.length),
      decoder
    ).get

    R1Data(senderID, encShares, coeffsCommitments, proof)
  }
}

//extends BytesSerializable {
//override type M = R1Data
//override type DECODER = (DiscreteLogGroup, BlockCipher)
//override val serializer: Serializer[M, DECODER] = R1DataSerializer
//}
//
//object R1DataSerializer extends Serializer[R1Data, (DiscreteLogGroup, BlockCipher)]{
//  def toBytes(obj: R1Data): Array[Byte]{
//
//  }
//
//  def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)] = None): Try[R1Data] = Try{
//
//  }
//}