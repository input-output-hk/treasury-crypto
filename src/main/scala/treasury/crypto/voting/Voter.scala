package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.nizk.shvzk.{SHVZKGen, SHVZKVerifier}

abstract class Voter {
  val cs: Cryptosystem
  val publicKey: PubKey

  def verifyBallot(ballot: Ballot): Boolean = {
    new SHVZKVerifier(cs, publicKey, ballot.getUnitVector, ballot.proof).verifyProof()
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
                   val stake: BigInteger) extends Voter {

  def produceVote(proposalID: Integer, choice: VoteCases.Value, withProof: Boolean = true): VoterBallot = {

    val nonZeroPos = choice match {
      case VoteCases.Yes      => 0
      case VoteCases.No       => 1
      case VoteCases.Abstain  => 2
    }

    val (uvDelegVector, uvDelegRand) = produceUnitVector(expertsNum, -1)
    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)
    val proof =
      if (withProof)
        new SHVZKGen(cs, publicKey, uvDelegVector ++ uvChoiceVector,
          expertsNum + nonZeroPos, uvDelegRand ++ uvChoiceRand).produceNIZK()
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }

  def produceDelegatedVote(proposalID: Integer, delegate: Int, withProof: Boolean = true): VoterBallot = {
    assert(delegate >= 0 && delegate < expertsNum)

    val (uvDelegVector, uvDelegRand) = produceUnitVector(expertsNum, delegate)
    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, -1)
    val proof =
      if (withProof)
        new SHVZKGen(cs, publicKey, uvDelegVector ++ uvChoiceVector, delegate, uvDelegRand ++ uvChoiceRand).produceNIZK()
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }
}

case class Expert(val cs: Cryptosystem,
                  val expertId: Int,
                  val publicKey: PubKey) extends Voter {

  def produceVote(proposalID: Integer, choice: VoteCases.Value, withProof: Boolean = true): ExpertBallot = {

    val nonZeroPos = choice match {
      case VoteCases.Yes      => 0
      case VoteCases.No       => 1
      case VoteCases.Abstain  => 2
    }

    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)
    val proof =
      if (withProof)
        new SHVZKGen(cs, publicKey, uvChoiceVector, nonZeroPos, uvChoiceRand).produceNIZK()
      else null

    ExpertBallot(proposalID, expertId, uvChoiceVector, proof)
  }
}