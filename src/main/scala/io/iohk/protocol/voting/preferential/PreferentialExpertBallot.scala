package io.iohk.protocol.voting.preferential

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertextSerializer
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.voting.Ballot
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try

case class PreferentialExpertBallot (expertId: Int,
                                     rankVectors: List[RankVector],
                                    ) extends PreferentialBallot {
  override type M = PreferentialBallot
  override val serializer = PreferentialBallotSerializer

  override val ballotTypeId: Byte = PreferentialBallotTypes.Expert.id.toByte

  override def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash}

    require(expertId >= 0 && expertId < pctx.numberOfExperts)
    require(rankVectors.size == pctx.numberOfProposals)
    rankVectors.foreach { v =>
      require(v.rank.size == pctx.numberOfRankedProposals)
      require(new SHVZKVerifier(pubKey, v.z+:v.rank, v.proof.get).verifyProof())
    }
  }.isSuccess
}

object PreferentialExpertBallot {

  def createBallot(pctx: PreferentialContext,
                   expertId: Int,
                   vote: DirectPreferentialVote,
                   ballotEncryptionKey: PubKey,
                   withProof: Boolean = true): Try[PreferentialExpertBallot] = Try {
    import pctx.cryptoContext.{group, hash}
    require(expertId >= 0 && expertId < pctx.numberOfExperts)
    require(vote.validate(pctx))

    val rankVectors = (0 until pctx.numberOfProposals).map { proposalId =>
      val nonZeroPos = vote.ranking.indexOf(proposalId) match {
        case -1 => 0 // there is no rank for proposal, in this case set z=1 and all other zeros. z bit is the first bit in vector
        case x => x + 1  // in case proposal is ranked, set corresponding bit to '1'
      }
      val (vector, rand) =
        Ballot.buildEncryptedUnitVector(size = pctx.numberOfRankedProposals + 1, nonZeroPos, ballotEncryptionKey)
      val proof = withProof match {
        case false => None
        case true => Some(new SHVZKGen(ballotEncryptionKey, vector, nonZeroPos, rand).produceNIZK().get)
      }
      RankVector(rank = vector.tail, z = vector.head, proof)
    }.toList

    PreferentialExpertBallot(expertId, rankVectors)
  }
}

/* PreferentialBallotSerializer should be used to deserialize PreferentialExpertBallot */
private[voting] object PreferentialExpertBallotSerializer extends Serializer[PreferentialExpertBallot, DiscreteLogGroup] {

  override def toBytes(ballot: PreferentialExpertBallot): Array[Byte] = {
    val rankVectorsBytes = ballot.rankVectors.foldLeft(Array[Byte]()) { (acc, v) =>
      val vectorBytes = (v.z +: v.rank).foldLeft(Array[Byte]()) { (acc2, b) =>
        val bytes = b.bytes
        Bytes.concat(acc2, Array(bytes.length.toByte), bytes)
      }
      val proofBytes = v.proof match {
        case Some(p) => p.bytes
        case None => Array[Byte]()
      }
      Bytes.concat(acc,
        Shorts.toByteArray((v.rank.length+1).toShort), vectorBytes,
        Ints.toByteArray(proofBytes.length), proofBytes)
    }

    Bytes.concat(
      Ints.toByteArray(ballot.expertId),
      Shorts.toByteArray(ballot.rankVectors.length.toShort), rankVectorsBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PreferentialExpertBallot] = Try {
    val expertId = Ints.fromByteArray(bytes.slice(0,4))
    val rankVectorsLen = Shorts.fromByteArray(bytes.slice(4,6))
    var position = 6

    val rankVectors = (0 until rankVectorsLen).map { _ =>
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
      RankVector(vector.tail, vector.head, proof)
    }.toList

    PreferentialExpertBallot(expertId, rankVectors)
  }
}