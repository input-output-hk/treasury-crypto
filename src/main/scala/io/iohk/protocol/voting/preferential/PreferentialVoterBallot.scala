package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.voting.Ballot
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try


case class PreferentialVoterBallot(delegVector: Vector[ElGamalCiphertext],
                                   delegVectorProof: Option[SHVZKProof],
                                   rankVectors: List[RankVector],
                                   w: ElGamalCiphertext,
                                   stake: BigInt
                                  ) extends PreferentialBallot {
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

    require(rankVectors.size == pctx.numberOfProposals)
    rankVectors.foreach { rv =>
      require(rv.rank.size == pctx.numberOfRankedProposals)
      val v = neg_w +: rv.z +: rv.rank
      require(new SHVZKVerifier(pubKey, v, rv.proof.get).verifyProof())
    }
  }.isSuccess
}

object PreferentialVoterBallot {

  def createBallot(pctx: PreferentialContext,
                   vote: PreferentialVote,
                   ballotEncryptionKey: PubKey,
                   stake: BigInt,
                   withProof: Boolean = true): Try[PreferentialVoterBallot] = Try {
    import pctx.cryptoContext.{group, hash}

    def prepareRankVectors(ranking: Option[List[Int]], w: ElGamalCiphertext, w_rand: Randomness) = {
      import pctx.cryptoContext.{group, hash}

      val one = LiftedElGamalEnc.encrypt(ballotEncryptionKey, 1, 1).get
      val neg_w = one / w
      val neg_w_rand = 1 - w_rand

      (0 until pctx.numberOfProposals).map { proposalId =>
        val nonZeroPos = ranking match {
          case Some(ranking) => ranking.indexOf(proposalId) match {
            case -1 => 0 // there is no rank for proposal, in this case set z=1 and all other zeros. z bit is the first bit in vector
            case x => x + 1 // in case proposal is ranked, set corresponding bit to '1'
          }
          case None => -1
        }
        val (vector, rand) =
          Ballot.buildEncryptedUnitVector(size = pctx.numberOfRankedProposals + 1, nonZeroPos, ballotEncryptionKey)
        val proof = withProof match {
          case true => Some(new SHVZKGen(ballotEncryptionKey, neg_w +: vector, nonZeroPos + 1, neg_w_rand +: rand).produceNIZK().get)
          case _ => None
        }
        RankVector(vector.tail, vector.head, proof)
      }.toList
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
        val rankVectors = prepareRankVectors(Some(ranking), w, w_rand)
        PreferentialVoterBallot(delegVector, delegVectorProof, rankVectors, w, stake)
      case DelegatedPreferentialVote(expertId) =>
        val (w, w_rand, delegVector, delegVectorProof) = prepareDelegationVectorWithProof(Some(expertId))
        val rankVectors= prepareRankVectors(None, w, w_rand)
        PreferentialVoterBallot(delegVector, delegVectorProof, rankVectors, w, stake)
    }
  }
}