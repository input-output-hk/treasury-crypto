package io.iohk.protocol.voting.approval.uni_delegation

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.voting.buildEncryptedUnitVector
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.UniDelegBallot.UniBallotTypes

import scala.util.Try

case class UniDelegExpertBallot(
  expertId: Int,
  choices: List[Vector[ElGamalCiphertext]],
  choicesProofs: Option[List[SHVZKProof]]
) extends UniDelegBallot {

  override type M = UniDelegExpertBallot
  override val serializer = UniDelegExpertBallotSerializer

  override val ballotTypeId: Byte = UniBallotTypes.Expert.id.toByte

  override def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash, commonReferenceString}
    require(choices.size == pctx.numberOfProposals)
    require(expertId >= 0 && expertId < pctx.numberOfExperts)
    choices.zip(choicesProofs.get).foreach { case (vector, proof) =>
      require(vector.size == pctx.numberOfChoices)
      require(new SHVZKVerifier(commonReferenceString, pubKey, vector, proof).verifyProof())
    }
  }.isSuccess
}

object UniDelegExpertBallot {

  def createBallot(pctx: ApprovalContext,
                   expertID: Int,
                   vote: DirectUniDelegVote,
                   ballotEncryptionKey: PubKey,
                   withProof: Boolean = true): Try[UniDelegExpertBallot] = Try {
    import pctx.cryptoContext.{group, hash}
    require(vote.validate(pctx), "Invalid vote!")
    require(expertID >= 0 && expertID < pctx.numberOfExperts, "Invalid expert ID!")

    val encryptedChoices = vote.getDirectVote.get.map { choice =>
      val (vector, rand) = buildEncryptedUnitVector(pctx.numberOfChoices, choice, ballotEncryptionKey)
      (choice, vector, rand)
    }
    val proofs = withProof match {
      case true =>
        val crs = pctx.cryptoContext.commonReferenceString
        Some(encryptedChoices.map { case (choice, vector, rand) =>
          new SHVZKGen(crs, ballotEncryptionKey, vector, choice, rand).produceNIZK().get
        })
      case _ => None
    }

    UniDelegExpertBallot(expertID, encryptedChoices.map(_._2), proofs)
  }
}

private[uni_delegation] object UniDelegExpertBallotSerializer extends Serializer[UniDelegExpertBallot, DiscreteLogGroup] {
  override def toBytes(ballot: UniDelegExpertBallot): Array[Byte] = {
    val choicesBytes = ballot.choices.foldLeft(Array[Byte]()) { (acc, v) =>
      val vectorBytes = v.foldLeft(Array[Byte]()) { (acc2, b) =>
        val bytes = b.bytes
        Bytes.concat(acc2, Array(bytes.length.toByte), bytes)
      }
      Bytes.concat(acc, Shorts.toByteArray(v.length.toShort), vectorBytes)
    }

    val proofBytes = ballot.choicesProofs.map { proofs =>
      proofs.foldLeft(Array[Byte]()) { (acc, p) =>
        val bytes = p.bytes
        Bytes.concat(acc, Shorts.toByteArray(bytes.length.toShort), bytes)
      }
    }.getOrElse(Array[Byte]())

    Bytes.concat(
      Ints.toByteArray(ballot.expertId),
      Shorts.toByteArray(ballot.choices.length.toShort), choicesBytes,
      Shorts.toByteArray(ballot.choicesProofs.map(_.length.toShort).getOrElse(0)), proofBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[UniDelegExpertBallot] = Try {
    val expertId = Ints.fromByteArray(bytes.slice(0,4))
    val choicesLen = Shorts.fromByteArray(bytes.slice(4,6))
    var position = 6

    val choices = (0 until choicesLen).map { _ =>
      val vectorLen = Shorts.fromByteArray(bytes.slice(position,position+2))
      position += 2
      (0 until vectorLen).map { _ =>
        val len = bytes(position)
        val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
        position = position + len + 1
        c
      }.toVector
    }.toList

    val proofsLen = Shorts.fromByteArray(bytes.slice(position, position+2))
    position += 2
    val proofs = proofsLen match {
      case 0 => None
      case len => Some({
        (0 until len).map { _ =>
          val l = Shorts.fromByteArray(bytes.slice(position, position+2))
          position = position + l + 2
          SHVZKProofSerializer.parseBytes(bytes.slice(position-l, position), decoder).get
        }.toList
      })
    }

    UniDelegExpertBallot(expertId, choices, proofs)
  }
}
