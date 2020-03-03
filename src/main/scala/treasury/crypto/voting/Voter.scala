package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.primitives.hash.CryptographicHash
import treasury.crypto.nizk.shvzk.{SHVZKGen, SHVZKVerifier}
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

abstract class Voter(implicit dlogGroup: DiscreteLogGroup, hash: CryptographicHash) {
  def cs: Cryptosystem
  def publicKey: PubKey

  def verifyBallot(ballot: Ballot): Boolean = {
    new SHVZKVerifier(publicKey, ballot.unitVector, ballot.proof).verifyProof()
  }

  protected def produceUnitVector(size: Int, nonZeroPos: Int): (Array[Ciphertext], Array[Randomness]) = {
    val ciphertexts = new Array[Ciphertext](size)
    val randomness = new Array[Randomness](size)

    for (i <- 0 until size) {
      randomness(i) = cs.getRand
      ciphertexts(i) = cs.encrypt(publicKey, randomness(i), if (i == nonZeroPos) One else Zero)
    }

    (ciphertexts, randomness)
  }
}

object Voter {
  val VOTER_CHOISES_NUM = 3
}

class RegularVoter(val cs: Cryptosystem,
                   val expertsNum: Integer,
                   val publicKey: PubKey,
                   val stake: BigInteger)
                  (implicit dlogGroup: DiscreteLogGroup, hash: CryptographicHash) extends Voter {

  def produceVote(proposalID: Integer, choice: VotingOptions.Value, withProof: Boolean = true): VoterBallot = {

    val nonZeroPos = choice match {
      case VotingOptions.Yes      => 0
      case VotingOptions.No       => 1
      case VotingOptions.Abstain  => 2
    }

    val (uvDelegVector, uvDelegRand) = produceUnitVector(expertsNum, -1)
    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvDelegVector ++ uvChoiceVector,
          expertsNum + nonZeroPos, uvDelegRand ++ uvChoiceRand).produceNIZK().get
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }

  def produceDelegatedVote(proposalID: Integer, delegate: Int, withProof: Boolean = true): VoterBallot = {
    assert(delegate >= 0 && delegate < expertsNum)

    val (uvDelegVector, uvDelegRand) = produceUnitVector(expertsNum, delegate)
    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, -1)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvDelegVector ++ uvChoiceVector, delegate, uvDelegRand ++ uvChoiceRand).produceNIZK().get
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }
}

case class Expert(cs: Cryptosystem,
                  expertId: Int,
                  publicKey: PubKey)
                 (implicit dlogGroup: DiscreteLogGroup, hash: CryptographicHash) extends Voter {

  def produceVote(proposalID: Integer, choice: VotingOptions.Value, withProof: Boolean = true): ExpertBallot = {

    val nonZeroPos = choice match {
      case VotingOptions.Yes      => 0
      case VotingOptions.No       => 1
      case VotingOptions.Abstain  => 2
    }

    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvChoiceVector, nonZeroPos, uvChoiceRand).produceNIZK().get
      else null

    ExpertBallot(proposalID, expertId, uvChoiceVector, proof)
  }
}
