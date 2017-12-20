package treasury.crypto
import java.math.BigInteger

import treasury.crypto.core.{Cryptosystem, PubKey, VoteCases, Zero}
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.{Ballot, Expert, RegularVoter}

trait Elections {
  def run(sharedPubKey: PubKey): Seq[Ballot]
  def verify(tallyRes: Result): Boolean
}

case class ElectionsScenario1(cs: Cryptosystem) extends Elections {
  private val proposalID = 1
  private val votersNum = 2
  private val expertsNum = 2

  def run(sharedPubKey: PubKey): Seq[Ballot] = {
    val votersBallots =
      for (voterId <- expertsNum until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, expertsNum, sharedPubKey, BigInteger.valueOf(3))
          .produceDelegatedVote(proposalID, 1)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        Expert(cs, expertId, sharedPubKey)
          .produceVote(proposalID, VoteCases.Yes)
      }

    votersBallots ++ expertsBallots
  }

  def verify(tallyRes: Result): Boolean = {
    tallyRes.yes.equals(BigInteger.valueOf(6))&&
    tallyRes.no.equals(Zero) &&
    tallyRes.abstain.equals(Zero)
  }
}

case class ElectionsScenario2(cs: Cryptosystem) extends Elections
{
  private val MULTIPLIER = 2

  private val proposalID = 1
  private val votersNum = 10 * MULTIPLIER
  private val votersDelegatedNum = 20 * MULTIPLIER
  private val expertsNum = 5 * MULTIPLIER

  def run(sharedPubKey: PubKey): Seq[Ballot] =
  {
    val votersBallots =
      for (voterId <- expertsNum until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, expertsNum, sharedPubKey, BigInteger.valueOf(3))
          .produceVote(proposalID, if (voterId % 2 == 1) VoteCases.Yes else VoteCases.Abstain)
      }

    val votersDelegatedBallots =
      for (voterId <- (expertsNum + votersNum) until (expertsNum + votersNum + votersDelegatedNum)) yield {
        new RegularVoter(cs, expertsNum, sharedPubKey, BigInteger.valueOf(2))
          .produceDelegatedVote(proposalID, 0)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        Expert(cs, expertId, sharedPubKey)
          .produceVote(proposalID, VoteCases.No)
      }

    votersBallots ++ votersDelegatedBallots ++ expertsBallots
  }

  def verify(tallyRes: Result): Boolean = {
    tallyRes.yes.equals(BigInteger.valueOf(15 * MULTIPLIER)) &&
    tallyRes.no.equals(BigInteger.valueOf(40 * MULTIPLIER)) &&
    tallyRes.abstain.equals(BigInteger.valueOf(15 * MULTIPLIER))
  }
}
