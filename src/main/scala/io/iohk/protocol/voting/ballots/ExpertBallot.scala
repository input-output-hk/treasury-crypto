package io.iohk.protocol.voting.ballots

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKProof, SHVZKProofSerializer}
import io.iohk.protocol.voting.Voter
import io.iohk.protocol.voting.ballots.Ballot.BallotTypes

import scala.util.Try

case class ExpertBallot(
  proposalId: Int,
  expertId: Int,
  uvChoice: Vector[ElGamalCiphertext],
  proof: SHVZKProof
) extends Ballot {

  override type M = Ballot
  override val serializer = BallotSerializer

  override val ballotTypeId: Byte = BallotTypes.Expert.id.toByte

  def unitVector: Vector[ElGamalCiphertext] = uvChoice
}

object ExpertBallotSerializer extends Serializer[ExpertBallot, DiscreteLogGroup] {
  override def toBytes(b: ExpertBallot): Array[Byte] = {
    val uvBytes = b.unitVector.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val proofBytes = b.proof.bytes

    Bytes.concat(
      Ints.toByteArray(b.proposalId),
      Ints.toByteArray(b.expertId),
      uvBytes,
      Ints.toByteArray(proofBytes.length), proofBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[ExpertBallot] = Try {
    val proposalId = Ints.fromByteArray(bytes.slice(0,4))
    val expertId = Ints.fromByteArray(bytes.slice(4,8))
    var position = 8

    val uvChoice: Array[ElGamalCiphertext] = (0 until Voter.VOTER_CHOISES_NUM).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toArray

    val proofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    val proof = SHVZKProofSerializer.parseBytes(bytes.slice(position+4, position+4+proofLen), decoder).get

    ExpertBallot(proposalId, expertId, uvChoice.toVector, proof)
  }
}
