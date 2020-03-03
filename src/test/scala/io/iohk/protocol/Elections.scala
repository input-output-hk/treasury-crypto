package io.iohk.protocol

import java.math.BigInteger

import io.iohk.core.PubKey
import io.iohk.protocol.voting.{Expert, RegularVoter, VotingOptions}
import io.iohk.protocol.voting.Tally.Result
import io.iohk.protocol.voting.ballots.Ballot

trait Elections {
  def run(sharedPubKey: PubKey): Seq[Ballot]
  def verify(tallyRes: Result): Boolean
}

case class ElectionsScenario1(cs: Cryptosystem) extends Elections {
  private val proposalID = 1
  private val votersNum = 2
  private val expertsNum = 2

  import cs.{group, hash}

  def run(sharedPubKey: PubKey): Seq[Ballot] = {
    val votersBallots =
      for (voterId <- expertsNum until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, expertsNum, sharedPubKey, BigInteger.valueOf(3))
          .produceDelegatedVote(proposalID, 1)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        Expert(cs, expertId, sharedPubKey)
          .produceVote(proposalID, VotingOptions.Yes)
      }

    votersBallots ++ expertsBallots
  }

  def verify(tallyRes: Result): Boolean = {
    tallyRes.yes == 6 &&
    tallyRes.no == 0 &&
    tallyRes.abstain == 0
  }
}

case class ElectionsScenario2(cs: Cryptosystem) extends Elections
{

  private val MULTIPLIER = 2

  private val proposalID = 1
  private val votersNum = 10 * MULTIPLIER
  private val votersDelegatedNum = 20 * MULTIPLIER
  private val expertsNum = 5 * MULTIPLIER

  import cs.{group, hash}

  def run(sharedPubKey: PubKey): Seq[Ballot] =
  {
    val votersBallots =
      for (voterId <- expertsNum until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, expertsNum, sharedPubKey, BigInteger.valueOf(3))
          .produceVote(proposalID, if (voterId % 2 == 1) VotingOptions.Yes else VotingOptions.Abstain)
      }

    val votersDelegatedBallots =
      for (voterId <- (expertsNum + votersNum) until (expertsNum + votersNum + votersDelegatedNum)) yield {
        new RegularVoter(cs, expertsNum, sharedPubKey, BigInteger.valueOf(2))
          .produceDelegatedVote(proposalID, 0)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        Expert(cs, expertId, sharedPubKey)
          .produceVote(proposalID, VotingOptions.No)
      }

    votersBallots ++ votersDelegatedBallots ++ expertsBallots
  }

  def verify(tallyRes: Result): Boolean = {
    tallyRes.yes == 15 * MULTIPLIER &&
    tallyRes.no == 40 * MULTIPLIER &&
    tallyRes.abstain == 15 * MULTIPLIER
  }
}
