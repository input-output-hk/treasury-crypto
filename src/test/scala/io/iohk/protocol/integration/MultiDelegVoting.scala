package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.CommitteeMember
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.tally.{MultiDelegBallotsSummator, MultiDelegTally}
import io.iohk.protocol.voting.approval.multi_delegation._

import scala.util.Try

abstract class MultiDelegVoting(ctx: CryptoContext) extends VotingSimulator {

  class MultiDelegTallySimulator(override val pctx: ApprovalContext,
                                 override val tally: MultiDelegTally,
                                 override val summator: MultiDelegBallotsSummator,
                                 override val expertBallots: Seq[MultiDelegExpertBallot]) extends TallySimulator {
    override type TALLY = MultiDelegTally
    override type PCTX = ApprovalContext
  }

  override type RESULT = MultiDelegTally#RESULT

  def prepareBallots(sharedPubKey: PubKey): (Seq[MultiDelegVoterBallot], Seq[MultiDelegExpertBallot])
  def context: ApprovalContext

  override def runVoting: Try[RESULT] = Try {
    val keyPairs = Array.fill(20)(encryption.createKeyPair(ctx.group).get)
    val committeeMembersPubKeys = keyPairs.map(_._2)
    val committeeMembers = keyPairs.map(k => new CommitteeMember(context.cryptoContext, k, committeeMembersPubKeys))

    // Phase 1 - Distributed voting key generation
    val (sharedPubKey, dkgR1Data, dkgViolators) = DistributedKeyGenerationSimulator.runDKG(ctx, committeeMembers)

    // Phase 2 - Voting (issuing encrypted ballots)
    val (voterBallots, expertBallots) = prepareBallots(sharedPubKey)
    voterBallots.foreach(b => require(b.verifyBallot(context, sharedPubKey)))

    // Phase 3 - Tally (homomorphic summation of ballots and distributed decryption)
    val ballotsSummator = new MultiDelegBallotsSummator(context)
    voterBallots.foreach(ballotsSummator.addVoterBallot(_))

    val tally = new MultiDelegTally(context, committeeMembers.head.memberIdentifier, dkgViolators)
    val tallySimulator = new MultiDelegTallySimulator(context, tally, ballotsSummator, expertBallots)
    tallySimulator.runTally(committeeMembers.head.memberIdentifier, committeeMembers, dkgR1Data).get
  }

}

class MultiDelegVotingScenario1(ctx: CryptoContext) extends MultiDelegVoting(ctx) {
  private val proposalID = 1
  private val votersNum = 2
  private val numberOfExperts = 2

  override val context = new ApprovalContext(ctx, 3, numberOfExperts)

  def prepareBallots(sharedPubKey: PubKey): (Seq[MultiDelegPublicStakeBallot], Seq[MultiDelegExpertBallot]) = {
    val votersBallots =
      for (_ <- 0 until votersNum) yield
        MultiDelegPublicStakeBallot.createBallot(context, proposalID, DelegatedMultiDelegVote(1), sharedPubKey, 3).get

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield
        MultiDelegExpertBallot.createBallot(context, proposalID, expertId, DirectMultiDelegVote(0), sharedPubKey).get

    votersBallots -> expertsBallots
  }

  override def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = {
    if (tallyRes.size == 1) {
      tallyRes(proposalID)(0) == 6 &&
        tallyRes(proposalID)(1) == 0 &&
        tallyRes(proposalID)(2) == 0
    } else false
  }
}

class MultiDelegVotingScenario2(ctx: CryptoContext) extends MultiDelegVoting(ctx) {
  val proposalIDs = Set(4, 11)
  val votersNum = 10
  val votersDelegatedNum = 20
  val numberOfExperts = 5

  override val context = new ApprovalContext(ctx, 3, numberOfExperts)

  def prepareBallots(sharedPubKey: PubKey): (Seq[MultiDelegVoterBallot], Seq[MultiDelegExpertBallot]) =
  {
    proposalIDs.foldLeft((Seq[MultiDelegPublicStakeBallot](), Seq[MultiDelegExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
      val votersBallots =
        for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
          val vote = if (voterId % 2 == 1) DirectMultiDelegVote(0) else DirectMultiDelegVote(2)
          MultiDelegPublicStakeBallot.createBallot(context, proposalID, vote, sharedPubKey, stake = proposalID).get
        }

      val votersDelegatedBallots =
        for (_ <- 0 until votersDelegatedNum) yield
          MultiDelegPublicStakeBallot.createBallot(context, proposalID, DelegatedMultiDelegVote(0), sharedPubKey, stake = proposalID).get

      val expertsBallots =
        for (expertId <- 0 until numberOfExperts) yield
          MultiDelegExpertBallot.createBallot(context, proposalID, expertId, DirectMultiDelegVote(1), sharedPubKey).get

      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
    }
  }

  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = Try {
    require(tallyRes.size == 2)
    proposalIDs.foreach { id =>
      require(tallyRes(id)(0) == 5 * id)
      require(tallyRes(id)(1) == 20 * id)
      require(tallyRes(id)(2) == 5 * id)
    }
    true
  }.getOrElse(false)
}

  /* Test an election with private stake ballots */
class MultiDelegVotingScenario3(ctx: CryptoContext) extends MultiDelegVotingScenario2(ctx) {

  override def prepareBallots(sharedPubKey: PubKey): (Seq[MultiDelegPrivateStakeBallot], Seq[MultiDelegExpertBallot]) =
  {
    proposalIDs.foldLeft((Seq[MultiDelegPrivateStakeBallot](), Seq[MultiDelegExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
      val votersBallots =
        for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
          val choice = if (voterId % 2 == 1) 0 else 2
          MultiDelegPrivateStakeBallot.createBallot(context, proposalID, DirectMultiDelegVote(choice), sharedPubKey, stake = proposalID).get
        }

      val votersDelegatedBallots = for (_ <- 0 until votersDelegatedNum) yield
        MultiDelegPrivateStakeBallot.createBallot(context, proposalID, DelegatedMultiDelegVote(0), sharedPubKey, stake = proposalID).get

      val expertsBallots =
        for (expertId <- 0 until numberOfExperts) yield
          MultiDelegExpertBallot.createBallot(context, proposalID, expertId, DirectMultiDelegVote(1), sharedPubKey).get

      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
    }
  }
}

/* Test voting where there are 5 choices to select from */
class MultiDelegVotingScenario4(ctx: CryptoContext) extends MultiDelegVoting(ctx) {

  val proposalIDs = Set(3, 8)
  val votersNum = 30
  val votersDelegatedNum = 20

  override val context = new ApprovalContext(ctx, numberOfChoices = 5, numberOfExperts = 5)

  def prepareBallots(sharedPubKey: PubKey): (Seq[MultiDelegVoterBallot], Seq[MultiDelegExpertBallot]) =
  {
    proposalIDs.foldLeft((Seq[MultiDelegPublicStakeBallot](), Seq[MultiDelegExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
      val votersBallots =
        for (voterId <- 0 until votersNum) yield
          MultiDelegPublicStakeBallot.createBallot(context, proposalID, DirectMultiDelegVote(voterId % 5), sharedPubKey, stake = proposalID).get

      val votersDelegatedBallots =
        for (voterId <- 0 until votersDelegatedNum) yield
          MultiDelegPublicStakeBallot.createBallot(context, proposalID, DelegatedMultiDelegVote(voterId % 5), sharedPubKey, stake = proposalID).get

      val expertsBallots =
        for (expertId <- 0 until context.numberOfExperts) yield
          MultiDelegExpertBallot.createBallot(context, proposalID, expertId, DirectMultiDelegVote(1), sharedPubKey).get

      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
    }
  }

  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = Try {
    require(tallyRes.size == 2)
    proposalIDs.foreach { id =>
      require(tallyRes(id).size == 5)
      require(tallyRes(id)(0) == 6 * id)
      require(tallyRes(id)(1) == 26 * id)
      require(tallyRes(id)(3) == 6 * id)
      require(tallyRes(id)(4) == 6 * id)
    }
    true
  }.getOrElse(false)
}
