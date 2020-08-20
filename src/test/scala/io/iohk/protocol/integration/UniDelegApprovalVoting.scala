package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.CommitteeMember
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.tally.{UniDelegBallotsSummator, UniDelegTally}
import io.iohk.protocol.voting.approval.uni_delegation._

import scala.util.Try

abstract class UniDelegApprovalVoting(ctx: CryptoContext) extends VotingSimulator {

  class UniDelegTallySimulator(override val pctx: ApprovalContext,
                               override val tally: UniDelegTally,
                               override val summator: UniDelegBallotsSummator,
                               override val expertBallots: Seq[UniDelegExpertBallot]) extends TallySimulator {
    override type TALLY = UniDelegTally
    override type PCTX = ApprovalContext
  }

  override type RESULT = UniDelegTally#RESULT

  def prepareBallots(sharedPubKey: PubKey): (Seq[UniDelegVoterBallot], Seq[UniDelegExpertBallot])
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
    val ballotsSummator = new UniDelegBallotsSummator(context)
    voterBallots.foreach(ballotsSummator.addVoterBallot(_))

    val tally = new UniDelegTally(context, committeeMembers.head.memberIdentifier, dkgViolators)
    val tallySimulator = new UniDelegTallySimulator(context, tally, ballotsSummator, expertBallots)
    tallySimulator.runTally(committeeMembers.head.memberIdentifier, committeeMembers, dkgR1Data).get
  }
}

class UniDelegApprovalVotingScenario1(ctx: CryptoContext) extends UniDelegApprovalVoting(ctx) {
  private val numberOfProposals = 5
  private val numberOfVoters = 7
  private val numberOfExperts = 3

  override val context = new ApprovalContext(ctx, 3, numberOfExperts, numberOfProposals)

  def prepareBallots(sharedPubKey: PubKey): (Seq[UniDelegVoterBallot], Seq[UniDelegExpertBallot]) = {
    val votersBallots =
      for (_ <- 0 until numberOfVoters) yield
        UniDelegPublicStakeBallot.createBallot(context, DelegatedUniDelegVote(1), sharedPubKey, 3).get

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield
        UniDelegExpertBallot.createBallot(context, expertId, DirectUniDelegVote(List.fill(5)(1)), sharedPubKey).get

    votersBallots -> expertsBallots
  }

  override def verify(tallyRes: List[Vector[BigInt]]): Boolean = Try {
    require(tallyRes.size == numberOfProposals)
    tallyRes.foreach { r =>
      require(r(0) == 0 && r(2) == 0)
      require(r(1) == numberOfVoters * 3)
    }
  }.isSuccess
}

class UniDelegApprovalVotingScenario2(ctx: CryptoContext) extends UniDelegApprovalVoting(ctx) {
  private val numberOfProposals = 3
  private val numberOfVoters = 5
  private val numberOfExperts = 0

  override val context = new ApprovalContext(ctx, 5, numberOfExperts, numberOfProposals)

  def prepareBallots(sharedPubKey: PubKey): (Seq[UniDelegVoterBallot], Seq[UniDelegExpertBallot]) = {
    val votersBallots = Seq(
      UniDelegPublicStakeBallot.createBallot(context, DirectUniDelegVote(List(0,4,2)), sharedPubKey, 3).get,
      UniDelegPublicStakeBallot.createBallot(context, DirectUniDelegVote(List(1,1,1)), sharedPubKey, 3).get,
      UniDelegPublicStakeBallot.createBallot(context, DirectUniDelegVote(List(0,0,2)), sharedPubKey, 3).get,
      UniDelegPublicStakeBallot.createBallot(context, DirectUniDelegVote(List(3,0,1)), sharedPubKey, 3).get,
      )

    votersBallots -> Seq()
  }

  override def verify(tallyRes: List[Vector[BigInt]]): Boolean = Try {
    require(tallyRes.size == numberOfProposals)
    require(tallyRes(0)(0) == 6)
    require(tallyRes(0)(1) == 3)
    require(tallyRes(0)(2) == 0)
    require(tallyRes(0)(3) == 3)
    require(tallyRes(0)(4) == 0)

    require(tallyRes(1)(0) == 6)
    require(tallyRes(1)(1) == 3)
    require(tallyRes(1)(2) == 0)
    require(tallyRes(1)(3) == 0)
    require(tallyRes(1)(4) == 3)

    require(tallyRes(2)(0) == 0)
    require(tallyRes(2)(1) == 6)
    require(tallyRes(2)(2) == 6)
    require(tallyRes(2)(3) == 0)
    require(tallyRes(2)(4) == 0)
  }.isSuccess
}
