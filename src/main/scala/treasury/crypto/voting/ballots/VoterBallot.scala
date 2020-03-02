package treasury.crypto.voting.ballots

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints, Shorts}
import treasury.crypto.core.encryption.elgamal.ElGamalCiphertextSerializer
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.{Ciphertext, Cryptosystem}
import treasury.crypto.core.serialization.Serializer
import treasury.crypto.nizk.shvzk.{SHVZKProof, SHVZKProofSerializer}
import treasury.crypto.voting.Voter

import scala.util.Try

case class VoterBallot(
  proposalId: Int,
  uvDelegations: Array[Ciphertext],
  uvChoice: Array[Ciphertext],
  proof: SHVZKProof,
  stake: BigInteger
) extends Ballot {

  override type M = Ballot
  override val serializer = BallotSerializer

  override val ballotTypeId: Byte = VoterBallot.BallotTypeId

  def unitVector: Array[Ciphertext] = uvDelegations ++ uvChoice
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

    val unitVector: Array[Ciphertext] = (0 until uvLen).map { _ =>
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
    val stake = new BigInteger(bytes.slice(position+1, position+1+stakeLen))

    VoterBallot(proposalId, uvDelegations, uvChoices, proof, stake)
  }
}