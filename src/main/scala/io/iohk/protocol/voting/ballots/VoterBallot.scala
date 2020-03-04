package io.iohk.protocol.voting.ballots

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKProof, SHVZKProofSerializer}
import io.iohk.protocol.voting.Voter

import scala.util.Try

case class VoterBallot(
  proposalId: Int,
  uvDelegations: Array[ElGamalCiphertext],
  uvChoice: Array[ElGamalCiphertext],
  proof: SHVZKProof,
  stake: BigInt
) extends Ballot {

  override type M = Ballot
  override val serializer = BallotSerializer

  override val ballotTypeId: Byte = VoterBallot.BallotTypeId

  def unitVector: Array[ElGamalCiphertext] = uvDelegations ++ uvChoice
}

object VoterBallot {
  val BallotTypeId = 1.toByte
}

object VoterBallotSerializer extends Serializer[VoterBallot, DiscreteLogGroup] {
  override def toBytes(b: VoterBallot): Array[Byte] = {
    val uvBytes = b.unitVector.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val proofBytes = b.proof.bytes
    val stakeBytes = b.stake.toByteArray

    Bytes.concat(
      Ints.toByteArray(b.proposalId),
      Shorts.toByteArray(b.unitVector.length.toShort), uvBytes,
      Ints.toByteArray(proofBytes.length), proofBytes,
      Array(stakeBytes.length.toByte), stakeBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[VoterBallot] = Try {
    val group = decoder.get
    val proposalId = Ints.fromByteArray(bytes.slice(0,4))
    val uvLen = Shorts.fromByteArray(bytes.slice(4,6))
    var position = 6

    val unitVector: Array[ElGamalCiphertext] = (0 until uvLen).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toArray
    val (uvDelegations, uvChoices) = unitVector.splitAt(unitVector.length - Voter.VOTER_CHOISES_NUM)

    val proofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    val proof = SHVZKProofSerializer.parseBytes(bytes.slice(position+4, position+4+proofLen), decoder).get
    position = position + 4 + proofLen

    val stakeLen = bytes(position)
    val stake = BigInt(bytes.slice(position+1, position+1+stakeLen))

    VoterBallot(proposalId, uvDelegations, uvChoices, proof, stake)
  }
}