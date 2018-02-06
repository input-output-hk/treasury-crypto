package treasury.crypto.voting.ballots

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints, Shorts}
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
  override val serializer = BallotCompanion

  override val ballotTypeId: Byte = VoterBallot.BallotTypeId

  def unitVector: Array[Ciphertext] = uvDelegations ++ uvChoice
}

object VoterBallot {
  val BallotTypeId = 1.toByte
}

object VoterBallotCompanion extends Serializer[VoterBallot] {
  override def toBytes(b: VoterBallot): Array[Byte] = {
    val uvBytes = b.unitVector.foldLeft(Array[Byte]()) { (acc, b) =>
      val c1Bytes = b._1.getEncoded(true)
      val c2Bytes = b._2.getEncoded(true)
      Bytes.concat(acc,
        Array(c1Bytes.length.toByte), c1Bytes,
        Array(c2Bytes.length.toByte), c2Bytes)
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

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[VoterBallot] = Try {
    val proposalId = Ints.fromByteArray(bytes.slice(0,4))
    val uvLen = Shorts.fromByteArray(bytes.slice(4,6))
    var position = 6

    val unitVector: Array[Ciphertext] = (0 until uvLen).map { _ =>
      val c1Len = bytes(position)
      val c1 = cs.decodePoint(bytes.slice(position+1, position+1+c1Len))
      position = position + c1Len + 1
      val c2Len = bytes(position)
      val c2 = cs.decodePoint(bytes.slice(position+1, position+1+c2Len))
      position = position + c2Len + 1
      (c1, c2)
    }.toArray
    val (uvDelegations, uvChoices) = unitVector.splitAt(unitVector.length - Voter.VOTER_CHOISES_NUM)

    val proofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    val proof = SHVZKProofSerializer.parseBytes(bytes.slice(position+4, position+4+proofLen), cs).get
    position = position + 4 + proofLen

    val stakeLen = bytes(position)
    val stake = new BigInteger(bytes.slice(position+1, position+1+stakeLen))

    VoterBallot(proposalId, uvDelegations, uvChoices, proof, stake)
  }
}