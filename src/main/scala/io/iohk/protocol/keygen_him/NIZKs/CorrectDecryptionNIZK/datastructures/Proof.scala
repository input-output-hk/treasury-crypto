package io.iohk.protocol.keygen_him.NIZKs.CorrectDecryptionNIZK.datastructures

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.nizk.{DLEQStandardNIZKProof, DLEQStandardNIZKProofSerializer}

import scala.util.Try

case class Proof(dlEqProof: DLEQStandardNIZKProof)
  extends BytesSerializable {
  override type M = Proof
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ProofSerializer
}

object ProofSerializer extends Serializer[Proof, DiscreteLogGroup]{
  def toBytes(obj: Proof): Array[Byte] = {
    obj.dlEqProof.bytes
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Proof] = Try{
    Proof(DLEQStandardNIZKProofSerializer.parseBytes(bytes, decoder).get)
  }

  def dummy(dlogGroup: DiscreteLogGroup): Proof = {
    Proof(DLEQStandardNIZKProof(dlogGroup.groupIdentity, dlogGroup.groupIdentity, BigInt(0)))
  }
}
