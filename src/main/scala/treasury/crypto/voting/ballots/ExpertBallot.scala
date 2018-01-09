package treasury.crypto.voting.ballots

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.{Ciphertext, Cryptosystem}
import treasury.crypto.core.serialization.Serializer
import treasury.crypto.nizk.shvzk.{SHVZKProof, SHVZKProofCompanion}
import treasury.crypto.voting.Voter

import scala.util.Try

case class ExpertBallot(
  proposalId: Int,
  expertId: Int,
  uvChoice: Array[Ciphertext],
  proof: SHVZKProof
) extends Ballot {

  override type M = Ballot
  override val serializer = BallotCompanion

  override val ballotTypeId: Byte = ExpertBallot.BallotTypeId

  def unitVector: Array[Ciphertext] = uvChoice
}

object ExpertBallot {
  val BallotTypeId = 2.toByte
}

object ExpertBallotCompanion extends Serializer[ExpertBallot] {
  override def toBytes(b: ExpertBallot): Array[Byte] = {
    val uvBytes = b.unitVector.foldLeft(Array[Byte]()) { (acc, b) =>
      val c1Bytes = b._1.getEncoded(true)
      val c2Bytes = b._2.getEncoded(true)
      Bytes.concat(acc,
        Array(c1Bytes.length.toByte), c1Bytes,
        Array(c2Bytes.length.toByte), c2Bytes)
    }
    val proofBytes = b.proof.bytes

    Bytes.concat(
      Ints.toByteArray(b.proposalId),
      Ints.toByteArray(b.expertId),
      uvBytes,
      Ints.toByteArray(proofBytes.length), proofBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[ExpertBallot] = Try {
    val proposalId = Ints.fromByteArray(bytes.slice(0,4))
    val expertId = Ints.fromByteArray(bytes.slice(4,8))
    var position = 8

    val uvChoice: Array[Ciphertext] = (0 until Voter.VOTER_CHOISES_NUM).map { _ =>
      val c1Len = bytes(position)
      val c1 = cs.decodePoint(bytes.slice(position+1, position+1+c1Len))
      position = position + c1Len + 1
      val c2Len = bytes(position)
      val c2 = cs.decodePoint(bytes.slice(position+1, position+1+c2Len))
      position = position + c2Len + 1
      (c1, c2)
    }.toArray

    val proofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    val proof = SHVZKProofCompanion.parseBytes(bytes.slice(position+4, position+4+proofLen), cs).get

    ExpertBallot(proposalId, expertId, uvChoice, proof)
  }
}
