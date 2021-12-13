package io.iohk.protocol.voting.approval.uni_delegation

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.UniDelegBallot.UniBallotTypes
import io.iohk.protocol.voting.buildEncryptedUnitVector

import scala.util.Try

case class UniDelegPublicStakeBallot(delegationVector: Vector[ElGamalCiphertext],
                                     delegationVectorProof: Option[SHVZKProof],
                                     choiceVectors: List[ChoiceVector],
                                     w: Option[ElGamalCiphertext],
                                     stake: BigInt) extends UniDelegVoterBallot {
  override type M = UniDelegBallot
  override val serializer = UniDelegBallotSerializer

  override val ballotTypeId: Byte = UniBallotTypes.Voter.id.toByte

  override def weightedDelegationVector(implicit group: DiscreteLogGroup): Vector[ElGamalCiphertext] = {
    delegationVector.map(v => v.pow(stake).get)
  }

  override def weightedChoiceVectors(implicit group: DiscreteLogGroup): List[Vector[ElGamalCiphertext]] = {
    choiceVectors.map(_.choice.map(v => v.pow(stake).get))
  }

  override def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash, commonReferenceString}
    val crs = commonReferenceString

    require(stake >= 0)
    require(delegationVector.size == pctx.numberOfExperts)
    val neg_w =
      if (pctx.numberOfExperts > 0) {
        require(new SHVZKVerifier(crs, pubKey, w.get +: delegationVector, delegationVectorProof.get).verifyProof())
        val one = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get
        Vector(one / w.get)
      } else Vector()

    require(choiceVectors.size == pctx.numberOfProposals)
    choiceVectors.foreach { rv =>
      require(rv.choice.size == pctx.numberOfChoices)
      val v = neg_w ++ rv.choice
      require(new SHVZKVerifier(crs, pubKey, v, rv.proof.get).verifyProof())
    }
  }.isSuccess
}

object UniDelegPublicStakeBallot {

  def createBallot(pctx: ApprovalContext,
                   vote: UniDelegVote,
                   ballotEncryptionKey: PubKey,
                   stake: BigInt,
                   withProof: Boolean = true): Try[UniDelegPublicStakeBallot] = Try {
    import pctx.cryptoContext.{group, hash, commonReferenceString}
    val crs = commonReferenceString

    def prepareChoiceVectors(choices: Option[List[Int]], w: Option[ElGamalCiphertext], w_rand: Option[Randomness]) = {
      import pctx.cryptoContext.{group, hash}

      val one = LiftedElGamalEnc.encrypt(ballotEncryptionKey, 1, 1).get
      val neg_w = w.map(w => Vector(one / w)).getOrElse(Vector())
      val neg_w_rand = w_rand.map(w_rand => Vector(1 - w_rand)).getOrElse(Vector())

      (0 until pctx.numberOfProposals).map { proposalId =>
        val nonZeroPos = choices.map(x => x(proposalId)).getOrElse(-1)
        val (vector, rand) = buildEncryptedUnitVector(size = pctx.numberOfChoices, nonZeroPos, ballotEncryptionKey)
        val proof = withProof match {
          case true =>
            Some(new SHVZKGen(crs, ballotEncryptionKey, neg_w ++ vector, nonZeroPos + neg_w.size, neg_w_rand ++ rand).produceNIZK().get)
          case _ => None
        }
        ChoiceVector(vector, proof)
      }.toList
    }

    def prepareDelegationVectorWithProof(expertId: Option[Int]) = {
      if (pctx.numberOfExperts <= 0)
        (None, None, Vector(), None)
      else {
        val nonZeroBitPosition = expertId.map(_ + 1).getOrElse(0)
        val (vector, rand) =
          buildEncryptedUnitVector(size = pctx.numberOfExperts + 1, nonZeroBitPosition, ballotEncryptionKey)
        val proof = withProof match {
          case true => Some(new SHVZKGen(crs, ballotEncryptionKey, vector, nonZeroBitPosition, rand).produceNIZK().get)
          case _ => None
        }
        (Some(vector.head), Some(rand.head), vector.tail, proof)
      }
    }

    require(vote.validate(pctx), "Invalid vote!")
    require(stake > 0, "Invalid stake amount!")

    vote match {
      case DirectUniDelegVote(choices) =>
        val (w, w_rand, delegVector, delegVectorProof) = prepareDelegationVectorWithProof(None)
        val choiceVectors = prepareChoiceVectors(Some(choices), w, w_rand)
        UniDelegPublicStakeBallot(delegVector, delegVectorProof, choiceVectors, w, stake)
      case DelegatedUniDelegVote(expertId) =>
        val (w, w_rand, delegVector, delegVectorProof) = prepareDelegationVectorWithProof(Some(expertId))
        val choiceVectors = prepareChoiceVectors(None, w, w_rand)
        UniDelegPublicStakeBallot(delegVector, delegVectorProof, choiceVectors, w, stake)
    }
  }
}

case class ChoiceVector(choice: Vector[ElGamalCiphertext], proof: Option[SHVZKProof])

/* Use UniDelegBallotSerializer to deserialize UniDelegPublicStakeBallot */
private[uni_delegation]
object UniDelegPublicStakeBallotSerializer extends Serializer[UniDelegPublicStakeBallot, DiscreteLogGroup] {
  override def toBytes(ballot: UniDelegPublicStakeBallot): Array[Byte] = {
    val delegBytes = ballot.delegationVector.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val delegationVectorProofBytes = ballot.delegationVectorProof.map(_.bytes).getOrElse(Array[Byte]())

    val choiceVectorsBytes = ballot.choiceVectors.foldLeft(Array[Byte]()) { (acc, v) =>
      val vectorBytes = v.choice.foldLeft(Array[Byte]()) { (acc2, b) =>
        val bytes = b.bytes
        Bytes.concat(acc2, Array(bytes.length.toByte), bytes)
      }
      val proofBytes = v.proof match {
        case Some(p) => p.bytes
        case None => Array[Byte]()
      }
      Bytes.concat(acc,
        Shorts.toByteArray(v.choice.length.toShort), vectorBytes,
        Ints.toByteArray(proofBytes.length), proofBytes)
    }

    val wBytes = ballot.w.map(_.bytes).getOrElse(Array[Byte]())
    val stakeBytes = ballot.stake.toByteArray

    Bytes.concat(
      Shorts.toByteArray(ballot.delegationVector.size.toShort), delegBytes,
      Ints.toByteArray(delegationVectorProofBytes.size), delegationVectorProofBytes,
      Shorts.toByteArray(ballot.choiceVectors.length.toShort), choiceVectorsBytes,
      Array(wBytes.length.toByte), wBytes,
      Array(stakeBytes.length.toByte), stakeBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[UniDelegPublicStakeBallot] = Try {
    val delegVectorLen = Shorts.fromByteArray(bytes.slice(0,2))
    var position = 2

    val delegVector = (0 until delegVectorLen).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toVector

    val delegVectorProofLen =  Ints.fromByteArray(bytes.slice(position,position+4))
    position += 4
    val delegVectorProof = delegVectorProofLen match {
      case 0 => None
      case l =>
        position = position + l
        Some(SHVZKProofSerializer.parseBytes(bytes.slice(position - l, position), decoder).get)
    }

    val choiceVectorsLen = Shorts.fromByteArray(bytes.slice(position,position+2))
    position += 2

    val choiceVectors = (0 until choiceVectorsLen).map { _ =>
      val vectorLen = Shorts.fromByteArray(bytes.slice(position,position+2))
      position += 2
      val vector = (0 until vectorLen).map { _ =>
        val len = bytes(position)
        val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
        position = position + len + 1
        c
      }.toVector
      val proofLen = Ints.fromByteArray(bytes.slice(position,position+4))
      position += 4
      val proof = proofLen match {
        case 0 => None
        case l =>
          position = position + l
          Some(SHVZKProofSerializer.parseBytes(bytes.slice(position - l, position), decoder).get)
      }
      ChoiceVector(vector, proof)
    }.toList

    val wLen = bytes(position)
    position += 1
    val w = wLen match {
      case 0 => None
      case l =>
        position += wLen
        Some(ElGamalCiphertextSerializer.parseBytes(bytes.slice(position - wLen, position), decoder).get)
    }

    val stakeLen = bytes(position)
    val stake = BigInt(bytes.slice(position+1, position+1+stakeLen))

    UniDelegPublicStakeBallot(delegVector, delegVectorProof, choiceVectors, w, stake)
  }
}