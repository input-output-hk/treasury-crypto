package io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize

case class Proof(commitment: Commitment, response: Response)
  extends BytesSerializable with HasSize {
  override type M = Proof
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ProofSerializer
  def size: Int = bytes.length
}

object ProofSerializer extends Serializer[Proof, DiscreteLogGroup]{
  def toBytes(obj: Proof): Array[Byte] = {
    val commitmentBytes = obj.commitment.bytes
    val responseBytes = obj.response.bytes

    Bytes.concat(
      Ints.toByteArray(commitmentBytes.length),
      commitmentBytes,
      // no need to save response's length - just read it till the end of serialized bytes
      responseBytes
    )
  }

  import scala.util.Try

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Proof] = Try{
    val commitmentSize = Ints.fromByteArray(bytes.slice(0, Ints.BYTES))
    val responseOffset = Ints.BYTES + commitmentSize

    Proof(
      CommitmentSerializer.parseBytes(bytes.slice(Ints.BYTES, responseOffset), decoder).get,
      ResponseSerializer.parseBytes(bytes.slice(responseOffset, bytes.length), decoder).get
    )
  }
}
