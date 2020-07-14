package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.voting.Ballot
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try


case class PreferentialVoterBallot(delegVector: Vector[ElGamalCiphertext],
                                   rankVectors: List[Vector[ElGamalCiphertext]],
                                   w: ElGamalCiphertext,
                                   delegVectorProof: Option[SHVZKProof],
                                   rankVectorsProofs: Option[List[SHVZKProof]],
                                   stake: BigInt
                                  ) extends PreferentialBallot(rankVectors, rankVectorsProofs) {
  override type M = PreferentialBallot
  override val serializer = PreferentialBallotSerializer

  override val ballotTypeId: Byte = PreferentialBallotTypes.Voter.id.toByte

//
//  def weightedUnitVector(implicit group: DiscreteLogGroup): EncryptedUnitVector = {
//    EncryptedUnitVector(
//      uVector.delegations.map(v => v.pow(stake).get),
//      uVector.choice.map(v => v.pow(stake).get)
//    )
//  }

  override def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash}

    require(stake >= 0)
    require(delegVector.size == pctx.numberOfExperts)
    require(new SHVZKVerifier(pubKey, w +: delegVector, delegVectorProof.get).verifyProof())

    val one = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get
    val neg_w = one / w

    require(rankVectors.size == pctx.numberOfRankedProposals)
    rankVectors.foreach(v => require(v.size == pctx.numberOfProposals))
    rankVectors.indices.foreach { i =>
      val v = neg_w +: rankVectors(i)
      val proof = rankVectorsProofs.get(i)
      require(new SHVZKVerifier(pubKey, v, proof).verifyProof())
    }
  }.isSuccess
}

object PreferentialVoterBallot {

  def createPreferentialVoterBallot(pctx: PreferentialContext,
                                    vote: PreferentialVote,
                                    ballotEncryptionKey: PubKey,
                                    stake: BigInt,
                                    withProof: Boolean = true): Try[PreferentialVoterBallot] = Try {
    import pctx.cryptoContext.{group,hash}

    def prepareRankVectorsWithProofs(ranking: Option[List[Int]], w: ElGamalCiphertext, w_rand: Randomness) = {
      import pctx.cryptoContext.{group,hash}

      val one = LiftedElGamalEnc.encrypt(ballotEncryptionKey, 1, 1).get
      val neg_w = one / w
      val neg_w_rand = 1 - w_rand

      val rankVectorsWithProofs =
        for (i <- 0 until pctx.numberOfRankedProposals) yield {
          val nonZeroBitPosition = ranking.map(r => r(i)).getOrElse(-1)
          val (vector, rand) =
            Ballot.buildEncryptedUnitVector(size = pctx.numberOfProposals, nonZeroBitPosition, ballotEncryptionKey)
          val proof = withProof match {
            case true => Some(new SHVZKGen(ballotEncryptionKey, neg_w +: vector, nonZeroBitPosition + 1, neg_w_rand +: rand).produceNIZK().get)
            case _ => None
          }
          (vector, proof)
        }

      val rankVectors = rankVectorsWithProofs.map(_._1).toList
      val proofs = withProof match {
        case true => Some(rankVectorsWithProofs.map(_._2.get).toList)
        case false => None
      }
      (rankVectors, proofs)
    }

    def prepareDelegationVectorWithProof(expertId: Option[Int]) = {
      val nonZeroBitPosition = expertId.map(_ + 1).getOrElse(0)
      val (vector, rand) =
        Ballot.buildEncryptedUnitVector(size = pctx.numberOfExperts + 1, nonZeroBitPosition, ballotEncryptionKey)
      val proof = withProof match {
        case true => Some(new SHVZKGen(ballotEncryptionKey, vector, nonZeroBitPosition, rand).produceNIZK().get)
        case _ => None
      }
      (vector.head, rand.head, vector.tail, proof)
    }

    require(stake > 0)
    require(vote.validate(pctx))

    vote match {
      case DirectPreferentialVote(ranking) =>
        val (w, w_rand, delegVector, delegVectorProof) = prepareDelegationVectorWithProof(None)
        val (rankVectors, rankVectorsProofs) = prepareRankVectorsWithProofs(Some(ranking), w, w_rand)
        PreferentialVoterBallot(delegVector, rankVectors, w, delegVectorProof, rankVectorsProofs, stake)
      case DelegatedPreferentialVote(expertId) =>
        val (w, w_rand, delegVector, delegVectorProof) = prepareDelegationVectorWithProof(Some(expertId))
        val (rankVectors, rankVectorsProofs) = prepareRankVectorsWithProofs(None, w, w_rand)
        PreferentialVoterBallot(delegVector, rankVectors, w, delegVectorProof, rankVectorsProofs, stake)
    }
  }
}