package io.iohk.protocol.voting

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer, LiftedElGamalEnc}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.nizk.MultRelationNIZK.MultRelationNIZKProof
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.nizk.{MultRelationNIZK, MultRelationNIZKProofSerializer}
import io.iohk.protocol.voting.Ballot.BallotTypes

import scala.util.Try

case class PrivateStakeBallot(override val proposalId: Int,
                              uVector: EncryptedUnitVector,
                              vVector: EncryptedUnitVector,
                              uProof: Option[SHVZKProof],
                              vProof: Option[MultRelationNIZKProof],
                              encryptedStake: ElGamalCiphertext
                             ) extends VoterBallot {

  override type M = Ballot
  override val serializer = BallotSerializer

  override val ballotTypeId: Byte = BallotTypes.PrivateVoter.id.toByte

  override def encryptedUnitVector = uVector
  override def weightedUnitVector(implicit g: DiscreteLogGroup) = vVector

  override def verifyBallot(pctx: ProtocolContext, pubKey: PubKey): Try[Unit] = Try {
    import pctx.cryptoContext.{group, hash}
    require(uVector.delegations.size == pctx.numberOfExperts)
    require(uVector.choice.size == pctx.numberOfChoices)
    require(vVector.delegations.size == pctx.numberOfExperts)
    require(vVector.choice.size == pctx.numberOfChoices)

    require(new SHVZKVerifier(pubKey, uVector.combine, uProof.get).verifyProof())
    require(MultRelationNIZK.verifyNIZK(pubKey, encryptedStake, uVector.combine, vVector.combine, vProof.get))
  }
}

object PrivateStakeBallot {
  /**
    *
    * @param proposalID
    * @param vote either VotingOptions (in case a voter votes directly) or expert id (in case delegation)
    * @param withProof
    * @return
    */
  def createBallot(pctx: ProtocolContext,
                   proposalID: Int,
                   vote: Vote,
                   ballotEncryptionKey: PubKey,
                   stake: BigInt,
                   withProof: Boolean = true): Try[PrivateStakeBallot] = Try {
    import pctx.cryptoContext.{group, hash}
    require(vote.validate(pctx), "Invalid vote!")
    require(stake > 0, "Invalid stake amount!")

    val nonZeroBitIndex = vote match {
      case DirectVote(v) => pctx.numberOfExperts + v
      case DelegatedVote(v) => v
    }

    val encryptedStake = LiftedElGamalEnc.encrypt(ballotEncryptionKey, stake).get._1

    // Step 1: building encrypted unit vector of voter's preference
    val (u, uRand) = Ballot.buildEncryptedUnitVector(pctx.numberOfExperts + pctx.numberOfChoices, nonZeroBitIndex, ballotEncryptionKey)
    val (uDeleg, uChoice) = u.splitAt(pctx.numberOfExperts)
    val uVector = EncryptedUnitVector(uDeleg, uChoice)
    val uProof =
      if (withProof)
        Some(new SHVZKGen(ballotEncryptionKey, u, nonZeroBitIndex, uRand).produceNIZK().get)
      else None

    // Step 2: building a vector of (a^e_i)*Enc(0), where 'a' is an encrypted stake and 'e_i' is a corresponding bit of a unit vector
    val plainUnitVector = Array.fill(u.size)(0)
    plainUnitVector(nonZeroBitIndex) = 1

    val vRand = Vector.fill(u.size)(group.createRandomNumber)
    val v = vRand.zip(plainUnitVector).map { case (r,bit) =>
      val st = encryptedStake.pow(bit).get
      val encryptedZero = LiftedElGamalEnc.encrypt(ballotEncryptionKey, r, 0).get
      st.multiply(encryptedZero).get
    }
    val vProof =
      if (withProof)
        Some(MultRelationNIZK.produceNIZK(ballotEncryptionKey, encryptedStake, plainUnitVector, uRand, vRand).get)
      else None
    val (vDeleg, vChoice) = v.splitAt(pctx.numberOfExperts)
    val vVector = EncryptedUnitVector(vDeleg, vChoice)

    PrivateStakeBallot(proposalID, uVector, vVector, uProof, vProof, encryptedStake)
  }
}

/* BallotSerializer should be used to deserialize PrivateVoterBallot */
private[voting] object PrivateVoterBallotSerializer extends Serializer[PrivateStakeBallot, DiscreteLogGroup] {

  override def toBytes(ballot: PrivateStakeBallot): Array[Byte] = {
    val uBytes = ballot.uVector.combine.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val uProofBytes = ballot.uProof.map(_.bytes).getOrElse(Array[Byte]())

    val vBytes = ballot.vVector.combine.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val vProofBytes = ballot.vProof.map(_.bytes).getOrElse(Array[Byte]())

    val stakeBytes = ballot.encryptedStake.bytes

    Bytes.concat(
      Ints.toByteArray(ballot.proposalId),
      Shorts.toByteArray(ballot.uVector.delegations.length.toShort), // we store only the size of 'u' vector because 'u' and 'v' should have equal size
      Shorts.toByteArray(ballot.uVector.choice.length.toShort),
      uBytes,
      vBytes,
      Ints.toByteArray(uProofBytes.length), uProofBytes,
      Ints.toByteArray(vProofBytes.length), vProofBytes,
      Array(stakeBytes.length.toByte), stakeBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PrivateStakeBallot] = Try {
    val proposalId = Ints.fromByteArray(bytes.slice(0,4))
    val uDelegVectorLen = Shorts.fromByteArray(bytes.slice(4,6))    // 'v' vector should have the same size
    val uChoiceVectorLen = Shorts.fromByteArray(bytes.slice(6,8))
    var position = 8

    val uVector: Vector[ElGamalCiphertext] = (0 until uDelegVectorLen + uChoiceVectorLen).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toVector
    val (uDelegations, uChoices) = uVector.splitAt(uDelegVectorLen)

    val vVector: Vector[ElGamalCiphertext] = (0 until uDelegVectorLen + uChoiceVectorLen).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toVector
    val (vDelegations, vChoices) = vVector.splitAt(uDelegVectorLen)

    val uProofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    position += 4
    val uProof = uProofLen match {
      case 0 => None
      case _ => {
        position += uProofLen
        Some(SHVZKProofSerializer.parseBytes(bytes.slice(position - uProofLen, position), decoder).get)
      }
    }

    val vProofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    position += 4
    val vProof = vProofLen match {
      case 0 => None
      case _ => {
        position += vProofLen
        Some(MultRelationNIZKProofSerializer.parseBytes(bytes.slice(position - vProofLen, position), decoder).get)
      }
    }

    val stakeLen = bytes(position)
    val encryptedStake = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+stakeLen), decoder).get

    PrivateStakeBallot(proposalId,
                      EncryptedUnitVector(uDelegations, uChoices),
                      EncryptedUnitVector(vDelegations, vChoices),
                      uProof,
                      vProof,
                      encryptedStake)
  }
}