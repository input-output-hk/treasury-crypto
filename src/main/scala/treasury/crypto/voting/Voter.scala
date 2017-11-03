package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._

abstract class Voter {
  val cs: Cryptosystem
  val publicKey: PubKey

  protected def produceUnitVector(size: Int, nonZeroPos: Int): Array[(Ciphertext, Randomness)] = {
    val unitVector = new Array[(Ciphertext, Randomness)](size)

    for (i <- 0 until size) {
      val rand = cs.getRand
      val encr = cs.encrypt(publicKey, rand, if (i == nonZeroPos) One else Zero)
      unitVector(i) = (encr, rand)
    }

    unitVector
  }
}

object Voter {
  val VOTER_CHOISES_NUM = 3
}

class RegularVoter(val cs: Cryptosystem,
                   val expertsNum: Integer,
                   val publicKey: PubKey,
                   val stake: BigInteger) extends Voter {

  def produceVote(proposalID: Integer, choice: VoteCases.Value): Ballot = {

    val nonZeroPos = choice match {
      case VoteCases.Yes      => 0
      case VoteCases.No       => 1
      case VoteCases.Abstain  => 2
    }

    val uvDelegations = produceUnitVector(expertsNum, -1)
    val uvChoice = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)

    VoterBallot(proposalID, uvDelegations.map(_._1), uvChoice.map(_._1), stake)
  }

  def produceDelegatedVote(proposalID: Integer, delegate: Int): Ballot = {
    assert(delegate >= 0 && delegate < expertsNum)

    val uvDelegations = produceUnitVector(expertsNum, delegate)
    val uvChoice = produceUnitVector(Voter.VOTER_CHOISES_NUM, -1)

    VoterBallot(proposalID, uvDelegations.map(_._1), uvChoice.map(_._1), stake)
  }
}

case class Expert(val cs: Cryptosystem,
                  val expertId: Int,
                  val publicKey: PubKey) extends Voter {

  def produceVote(proposalID: Integer, choice: VoteCases.Value): Ballot = {

    val nonZeroPos = choice match {
      case VoteCases.Yes      => 0
      case VoteCases.No       => 1
      case VoteCases.Abstain  => 2
    }

    val uvChoice = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)

    ExpertBallot(proposalID, expertId, uvChoice.map(_._1))
  }
}