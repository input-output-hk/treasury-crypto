package io.iohk.protocol.voting.ballots

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.voting.ballots.Ballot.BallotTypes
import io.iohk.protocol.voting.{UnitVector, Voter}

import scala.util.Try

case class VoterBallot(
  override val proposalId: Int,
  uVector: UnitVector,
  uProof: Option[SHVZKProof],
  stake: BigInt
) extends Ballot {

  override type M = Ballot
  override val serializer = BallotSerializer

  override val ballotTypeId: Byte = BallotTypes.Voter.id.toByte

  override def verifyBallot(pctx: ProtocolContext, pubKey: PubKey): Try[Unit] = Try {
    import pctx.cryptoContext.{group, hash}
    require(uVector.delegations.size == pctx.numberOfExperts)
    require(uVector.choice.size == pctx.numberOfChoices)
    require(new SHVZKVerifier(pubKey, uVector.combine, uProof.get).verifyProof())
  }

  // TODO: do we need this? The idea is to make common interface for public and private voters and then use it in BallotsSUmmator.
  // consider to create VoterBallot -> PublicStakeVoterBallot, PrivateStakeVoterBallot. This function will be in VoterBallot interface. And also add common functionality there.
  // do we really need to separate Voter and VoterBallot? we can have a static function create ballot
  //def weightedUnitVector(implicit group: DiscreteLogGroup) = unitVector.map(v => v.pow(stake).get)
}

object VoterBallot {

  def createBallot(pctx: ProtocolContext,
                   proposalID: Int,
                   vote: Int,
                   ballotEncryptionKey: PubKey,
                   stake: BigInt,
                   withProof: Boolean = true): Try[VoterBallot] = Try {
    import pctx.cryptoContext.{group, hash}
    require(vote >= 0 && vote < pctx.numberOfChoices + pctx.numberOfExperts, "Invalid vote!")
    require(stake > 0, "Invalid stake amount!")

    val (u, uRand) = Ballot.buildEncryptedUnitVector(pctx.numberOfExperts + pctx.numberOfChoices, vote, ballotEncryptionKey)
    val (uDeleg, uChoice) = u.splitAt(pctx.numberOfExperts)
    val uVector = UnitVector(uDeleg, uChoice)
    val uProof = withProof match {
      case true => Some(new SHVZKGen(ballotEncryptionKey, u, vote, uRand).produceNIZK().get)
      case _ => None
    }

    VoterBallot(proposalID, uVector, uProof, stake)
  }
}

/* BallotSerializer should be used to deserialize VoterBallot */
private[voting]
object VoterBallotSerializer extends Serializer[VoterBallot, DiscreteLogGroup] {
  override def toBytes(b: VoterBallot): Array[Byte] = {
    val uBytes = b.uVector.combine.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val proofBytes = b.uProof.map(_.bytes).getOrElse(Array[Byte]())
    val stakeBytes = b.stake.toByteArray

    Bytes.concat(
      Ints.toByteArray(b.proposalId),
      Shorts.toByteArray(b.uVector.delegations.length.toShort),
      Shorts.toByteArray(b.uVector.choice.length.toShort),
      uBytes,
      Ints.toByteArray(proofBytes.length), proofBytes,
      Array(stakeBytes.length.toByte), stakeBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[VoterBallot] = Try {
    val proposalId = Ints.fromByteArray(bytes.slice(0,4))
    val delegVectorLen = Shorts.fromByteArray(bytes.slice(4,6))
    val choiceVectorLen = Shorts.fromByteArray(bytes.slice(6,8))
    var position = 8

    val unitVector: Vector[ElGamalCiphertext] = (0 until delegVectorLen + choiceVectorLen).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toVector

    val (uDelegations, uChoices) = unitVector.splitAt(delegVectorLen)

    val proofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    position += 4
    val proof = proofLen match {
      case 0 => None
      case _ => {
        position += proofLen
        Some(SHVZKProofSerializer.parseBytes(bytes.slice(position-proofLen, position), decoder).get)
      }
    }

    val stakeLen = bytes(position)
    val stake = BigInt(bytes.slice(position+1, position+1+stakeLen))

    VoterBallot(proposalId, UnitVector(uDelegations, uChoices), proof, stake)
  }
}