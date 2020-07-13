package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.voting.{Ballot, DirectVote}
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try

case class PreferentialExpertBallot (expertId: Int,
                                     rankVectors: List[Vector[ElGamalCiphertext]],
                                     rankVectorsProofs: Option[List[SHVZKProof]]
                                    ) extends PreferentialBallot(rankVectors, rankVectorsProofs) {
  override type M = PreferentialBallot
  override val serializer = PreferentialBallotSerializer

  override val ballotTypeId: Byte = PreferentialBallotTypes.Expert.id.toByte

  override def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean =
    super.verifyBallot(pctx, pubKey) &&
    expertId >= 0 && expertId < pctx.numberOfExperts
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