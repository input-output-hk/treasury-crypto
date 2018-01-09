package treasury.crypto.voting

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints, Shorts}
import treasury.crypto.core._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.nizk.shvzk.{SHVZKProof, SHVZKProofCompanion}

import scala.util.{Failure, Try}

// The data structure for storing of the individual voter's/expert's choice
trait Ballot extends BytesSerializable {
  def ballotTypeId: Byte

  def proposalId: Int
  def proof: SHVZKProof

  def unitVector: Array[Ciphertext]
}

object BallotCompanion extends Serializer[Ballot] {
  override def toBytes(b: Ballot): Array[Byte] = b match {
    case v: VoterBallot => Bytes.concat(Array(v.ballotTypeId), VoterBallotCompanion.toBytes(v))
    case e: ExpertBallot => Bytes.concat(Array(e.ballotTypeId), ExpertBallotCompanion.toBytes(e))
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[Ballot] = Try {
    val ballotTypeId = bytes(0)
    ballotTypeId match {
      case id if id == VoterBallot.BallotTypeId => VoterBallotCompanion.parseBytes(bytes.drop(1), cs).get
      case id if id == ExpertBallot.BallotTypeId => ExpertBallotCompanion.parseBytes(bytes.drop(1), cs).get
    }
  }
}

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
    val proof = SHVZKProofCompanion.parseBytes(bytes.slice(position+4, position+4+proofLen), cs).get
    position = position + 4 + proofLen

    val stakeLen = bytes(position)
    val stake = new BigInteger(bytes.slice(position+1, position+1+stakeLen))

    VoterBallot(proposalId, uvDelegations, uvChoices, proof, stake)
  }
}

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