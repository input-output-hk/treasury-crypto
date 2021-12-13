package io.iohk.protocol.voting.approval.multi_delegation

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.MultiDelegBallot.MultiDelegBallotTypes
import io.iohk.protocol.voting.buildEncryptedUnitVector

import scala.util.Try

case class MultiDelegPublicStakeBallot(override val proposalId: Int,
                                       uVector: EncryptedUnitVector,
                                       uProof: Option[SHVZKProof],
                                       stake: BigInt) extends MultiDelegVoterBallot {
  override type M = MultiDelegBallot
  override val serializer = MultiDelegBallotSerializer

  override val ballotTypeId: Byte = MultiDelegBallotTypes.Voter.id.toByte

  def encryptedUnitVector = uVector

  def weightedUnitVector(implicit group: DiscreteLogGroup): EncryptedUnitVector = {
    EncryptedUnitVector(
      uVector.delegations.map(v => v.pow(stake).get),
      uVector.choice.map(v => v.pow(stake).get)
    )
  }

  override def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash, commonReferenceString}
    require(uVector.delegations.size == pctx.numberOfExperts)
    require(uVector.choice.size == pctx.numberOfChoices)
    require(new SHVZKVerifier(commonReferenceString, pubKey, uVector.combine, uProof.get).verifyProof())
  }.isSuccess
}

object MultiDelegPublicStakeBallot {

  def createBallot(pctx: ApprovalContext,
                   proposalID: Int,
                   vote: MultiDelegVote,
                   ballotEncryptionKey: PubKey,
                   stake: BigInt,
                   withProof: Boolean = true): Try[MultiDelegPublicStakeBallot] = Try {
    import pctx.cryptoContext.{group, hash}
    require(vote.validate(pctx), "Invalid vote!")
    require(stake > 0, "Invalid stake amount!")

    val nonZeroBitIndex = vote match {
      case DirectMultiDelegVote(v) => pctx.numberOfExperts + v
      case DelegatedMultiDelegVote(v) => v
    }
    val (u, uRand) = buildEncryptedUnitVector(pctx.numberOfExperts + pctx.numberOfChoices, nonZeroBitIndex, ballotEncryptionKey)
    val (uDeleg, uChoice) = u.splitAt(pctx.numberOfExperts)
    val uVector = EncryptedUnitVector(uDeleg, uChoice)
    val uProof = withProof match {
      case true =>
        val crs = pctx.cryptoContext.commonReferenceString
        Some(new SHVZKGen(crs, ballotEncryptionKey, u, nonZeroBitIndex, uRand).produceNIZK().get)
      case _ => None
    }

    MultiDelegPublicStakeBallot(proposalID, uVector, uProof, stake)
  }
}

/* BallotSerializer should be used to deserialize VoterBallot */
private[voting]
object MultiDelegPublicStakeBallotSerializer extends Serializer[MultiDelegPublicStakeBallot, DiscreteLogGroup] {
  override def toBytes(b: MultiDelegPublicStakeBallot): Array[Byte] = {
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

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[MultiDelegPublicStakeBallot] = Try {
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

    MultiDelegPublicStakeBallot(proposalId, EncryptedUnitVector(uDelegations, uChoices), proof, stake)
  }
}