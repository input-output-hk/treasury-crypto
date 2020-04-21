package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.tally.Tally.Result
import io.iohk.protocol.voting.ballots.{Ballot, ExpertBallot, VoterBallot}
import io.iohk.protocol.voting.{Expert, RegularVoter, VotingOptions}

import scala.util.Try

trait Elections {
  def run(sharedPubKey: PubKey): (Seq[VoterBallot], Seq[ExpertBallot])
  def verify(tallyRes: Map[Int, Result]): Boolean
  def numberOfExperts: Int
}

case class ElectionsScenario1(ctx: CryptoContext) extends Elections {
  private val proposalID = 1
  private val votersNum = 2
  override val numberOfExperts = 2

  def run(sharedPubKey: PubKey): (Seq[VoterBallot], Seq[ExpertBallot]) = {
    val votersBallots =
      for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
        new RegularVoter(ctx, numberOfExperts, sharedPubKey, 3)
          .produceDelegatedVote(proposalID, 1)
      }

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield {
        Expert(ctx, expertId, sharedPubKey)
          .produceVote(proposalID, VotingOptions.Yes)
      }

    votersBallots -> expertsBallots
  }

  def verify(tallyRes: Map[Int, Result]): Boolean = {
    if (tallyRes.size == 1) {
      tallyRes(proposalID).yes == 6 &&
      tallyRes(proposalID).no == 0 &&
      tallyRes(proposalID).abstain == 0
    } else false
  }
}

case class ElectionsScenario2(ctx: CryptoContext) extends Elections
{
  private val proposalIDs = Set(32, 48)
  private val votersNum = 10
  private val votersDelegatedNum = 20
  override val numberOfExperts = 5

  def run(sharedPubKey: PubKey): (Seq[VoterBallot], Seq[ExpertBallot]) =
  {
    proposalIDs.foldLeft((Seq[VoterBallot](), Seq[ExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
      val votersBallots =
        for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
          new RegularVoter(ctx, numberOfExperts, sharedPubKey, proposalID)
            .produceVote(proposalID, if (voterId % 2 == 1) VotingOptions.Yes else VotingOptions.Abstain)
        }

      val votersDelegatedBallots =
        for (voterId <- (numberOfExperts + votersNum) until (numberOfExperts + votersNum + votersDelegatedNum)) yield {
          new RegularVoter(ctx, numberOfExperts, sharedPubKey, proposalID)
            .produceDelegatedVote(proposalID, 0)
        }

      val expertsBallots =
        for (expertId <- 0 until numberOfExperts) yield {
          Expert(ctx, expertId, sharedPubKey)
            .produceVote(proposalID, VotingOptions.No)
        }

      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
    }
  }

  def verify(tallyRes: Map[Int, Result]): Boolean = Try {
    require(tallyRes.size == 2)
    proposalIDs.foreach { id =>
      require(tallyRes(id).yes == 5 * id)
      require(tallyRes(id).no == 20 * id)
      require(tallyRes(id).abstain == 5 * id)
    }
    true
  }.getOrElse(false)
}
