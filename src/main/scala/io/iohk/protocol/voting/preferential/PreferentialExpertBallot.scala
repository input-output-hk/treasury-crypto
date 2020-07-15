package io.iohk.protocol.voting.preferential

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.voting.{Ballot, DirectVote, ExpertBallot}
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try

case class PreferentialExpertBallot (expertId: Int,
                                     rankVectors: List[Vector[ElGamalCiphertext]],
                                     rankVectorsProofs: Option[List[SHVZKProof]]
                                    ) extends PreferentialBallot {
  override type M = PreferentialBallot
  override val serializer = PreferentialBallotSerializer

  override val ballotTypeId: Byte = PreferentialBallotTypes.Expert.id.toByte

  override def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash}

    require(expertId >= 0 && expertId < pctx.numberOfExperts)
    require(rankVectors.size == pctx.numberOfRankedProposals)
    rankVectors.foreach(v => require(v.size == pctx.numberOfProposals))
    rankVectors.indices.foreach { i =>
      require(new SHVZKVerifier(pubKey, rankVectors(i), rankVectorsProofs.get(i)).verifyProof())
    }
  }.isSuccess
}

object PreferentialExpertBallot {

  def createPreferentialExpertBallot(pctx: PreferentialContext,
                                     expertId: Int,
                                     vote: DirectPreferentialVote,
                                     ballotEncryptionKey: PubKey,
                                     withProof: Boolean = true): Try[PreferentialExpertBallot] = Try {
    import pctx.cryptoContext.{group,hash}
    require(expertId >= 0 && expertId < pctx.numberOfExperts)
    require(vote.validate(pctx))

    val rankVectorsWithProofs = vote.ranking.map { proposalId =>
      val nonZeroBitPosition = proposalId
      val (vector, rand) =
        Ballot.buildEncryptedUnitVector(size = pctx.numberOfProposals, nonZeroBitPosition, ballotEncryptionKey)
      val proof = withProof match {
        case true => Some(new SHVZKGen(ballotEncryptionKey, vector, nonZeroBitPosition, rand).produceNIZK().get)
        case _ => None
      }
      (vector, proof)
    }

    val rankVectors = rankVectorsWithProofs.map(_._1)
    val proofs = withProof match {
      case true => Some(rankVectorsWithProofs.map(_._2.get))
      case _ => None
    }

    PreferentialExpertBallot(expertId, rankVectors, proofs)
  }
}

/* PreferentialBallotSerializer should be used to deserialize PreferentialExpertBallot */
private[voting] object PreferentialExpertBallotSerializer extends Serializer[PreferentialExpertBallot, DiscreteLogGroup] {

  override def toBytes(ballot: PreferentialExpertBallot): Array[Byte] = {
    val rankVectorsBytes = ballot.rankVectors.foldLeft(Array[Byte]()) { (acc, v) =>
      val vectorBytes = v.foldLeft(Array[Byte]()) { (acc2, b) =>
        val bytes = b.bytes
        Bytes.concat(acc, Array(bytes.length.toByte), bytes)
      }
      Bytes.concat(acc, Shorts.toByteArray(v.length.toShort), vectorBytes)
    }

    val proofBytes = ballot.rankVectorsProofs.map { proofs =>
      proofs.foldLeft(Array[Byte]()) { (acc, p) =>
        val proofBytes = p.bytes
        Bytes.concat(acc, Ints.toByteArray(proofBytes.length), proofBytes)
      }
    }.getOrElse(Array[Byte]())

    Bytes.concat(
      Ints.toByteArray(ballot.expertId),
      Shorts.toByteArray(ballot.rankVectors.length.toShort), rankVectorsBytes,
      Shorts.toByteArray(ballot.rankVectorsProofs.map(_.length).getOrElse(0).toShort), proofBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PreferentialExpertBallot] = Try {
    val expertId = Ints.fromByteArray(bytes.slice(0,4))
    val rankVectorsLen = Shorts.fromByteArray(bytes.slice(4,6))
    var position = 6

    val rankVectors: List[Vector[ElGamalCiphertext]] = (0 until rankVectorsLen).map { _ =>
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
    val proofs: Option[List[SHVZKProof]] = proofsLen match {
      case 0 => None
      case _ => {
        val proofs = (0 until proofsLen).map { _ =>
          val len = Ints.fromByteArray(bytes.slice(position, position+4))
          val p = SHVZKProofSerializer.parseBytes(bytes.slice(position+4, position+len+4), decoder).get
          position = position + len + 4
          p
        }.toList
        Some(proofs)
      }
    }

    PreferentialExpertBallot(expertId, rankVectors, proofs)
  }
}