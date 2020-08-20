package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.CommitteeMember
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.tally.UniDelegTally.UniDelegStages
import io.iohk.protocol.voting.approval.uni_delegation.{DelegatedUniDelegVote, DirectUniDelegVote, UniDelegExpertBallot, UniDelegPublicStakeBallot, UniDelegVoterBallot}
import io.iohk.protocol.voting.approval.uni_delegation.tally.{UniDelegBallotsSummator, UniDelegTally}
import io.iohk.protocol.voting.preferential.tally.PreferentialTally.PrefStages
import io.iohk.protocol.voting.preferential.{DelegatedPreferentialVote, DirectPreferentialVote, PreferentialContext, PreferentialExpertBallot, PreferentialVoterBallot}
import io.iohk.protocol.voting.preferential.tally.{PreferentialBallotsSummator, PreferentialTally}

import scala.util.Try

abstract class TwoStageVoting(ctx: CryptoContext) extends VotingSimulator {

  import PreferentialVoting.PreferentialTallySimulator
  import UniDelegApprovalVoting.UniDelegTallySimulator

  override type RESULT = List[(Int, Vector[BigInt])]  // proposalId -> choices

  def preparePreferentialBallots(sharedPubKey: PubKey): (Seq[PreferentialVoterBallot], Seq[PreferentialExpertBallot])
  def prepareUniDelegBallots(sharedPubKey: PubKey): (Seq[UniDelegVoterBallot], Seq[UniDelegExpertBallot])
  def preferentialContext: PreferentialContext
  def approvalContext: ApprovalContext

  override def runVoting: Try[RESULT] = Try {
    val keyPairs = Array.fill(20)(encryption.createKeyPair(ctx.group).get)
    val committeeMembersPubKeys = keyPairs.map(_._2)
    val committeeMembers = keyPairs.map(k => new CommitteeMember(approvalContext.cryptoContext, k, committeeMembersPubKeys))

    // Preparation stage
    // Phase 1 - Distributed voting key generation
    val (sharedPubKey, dkgR1Data, dkgViolators) = DistributedKeyGenerationSimulator.runDKG(ctx, committeeMembers)

    // Preferential voting stage
    // Phase 2 - Preferential voting (issuing encrypted ballots)
    val (prefVoterBallots, prefExpertBallots) = preparePreferentialBallots(sharedPubKey)
    prefVoterBallots.foreach(b => require(b.verifyBallot(preferentialContext, sharedPubKey)))
    // Phase 3 - Preferential Tally (homomorphic summation of ballots and distributed decryption)
    val prefBallotsSummator = new PreferentialBallotsSummator(preferentialContext)
    prefVoterBallots.foreach(prefBallotsSummator.addVoterBallot(_))
    val prefTally = new PreferentialTally(preferentialContext, committeeMembers.head.memberIdentifier, dkgViolators)
    val prefTallySimulator = new PreferentialTallySimulator(preferentialContext, prefTally, prefBallotsSummator, prefExpertBallots)
    prefTallySimulator.runTally(committeeMembers.head.memberIdentifier, committeeMembers, dkgR1Data).get
    require(prefTally.getCurrentRound == PrefStages.TallyR4)

    // After the preferential stage we have a list of selected proposals, which goes to the second stage
    val preferentialWinners = prefTally.getSortedScores.get.take(approvalContext.numberOfProposals)

    // Approval voting stage
    // Phase 4 - Uni approval voting (issuing encrypted ballots)
    val (approvalVoterBallots, aprovalExpertBallots) = prepareUniDelegBallots(sharedPubKey)
    approvalVoterBallots.foreach(b => require(b.verifyBallot(approvalContext, sharedPubKey)))
    // Phase 5 - Uni approval tally (homomorphic summation of ballots and distributed decryption)
    val approvalBallotsSummator = new UniDelegBallotsSummator(approvalContext)
    approvalVoterBallots.foreach(approvalBallotsSummator.addVoterBallot(_))
    val approvalTally = new UniDelegTally(approvalContext, committeeMembers.head.memberIdentifier, prefTally.getAllDisqualifiedCommitteeKeys)
    val approvalTallySimulator = new UniDelegTallySimulator(approvalContext, approvalTally, approvalBallotsSummator, aprovalExpertBallots)
    approvalTallySimulator.runTally(committeeMembers.head.memberIdentifier, committeeMembers, dkgR1Data).get
    require(approvalTally.getCurrentRound == UniDelegStages.TallyR4)
    val approvalResult = approvalTally.getResult.get
    require(preferentialWinners.size == approvalResult.size)

    val proposalIds = preferentialWinners.map(_._1)
    val result = proposalIds.zip(approvalTally.getResult.get) // zip results with corresponding proposal ids, we assume that during the approval stage the proposals were sorted as after preferential stage
    result
  }
}

class TwoStageVotingScenario1(ctx: CryptoContext) extends TwoStageVoting(ctx) {
  private val numberOfProposalsStage1 = 10
  private val numberOfRankedProposals = 3
  private val numberOfProposalsStage2 = 5
  private val numberOfVoters = 7
  private val numberOfExperts = 3
  private val stake = 6

  override val preferentialContext = new PreferentialContext(ctx, numberOfProposalsStage1, numberOfRankedProposals, numberOfExperts)
  override val approvalContext = new ApprovalContext(ctx, 3, numberOfExperts, numberOfProposalsStage2)

  override def preparePreferentialBallots(sharedPubKey: PubKey): (Seq[PreferentialVoterBallot], Seq[PreferentialExpertBallot]) = {
    val votersBallots =
      for (_ <- 0 until numberOfVoters) yield
        PreferentialVoterBallot.createBallot(preferentialContext, DelegatedPreferentialVote(numberOfVoters % numberOfExperts), sharedPubKey, stake).get

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield
        PreferentialExpertBallot.createBallot(preferentialContext, expertId, DirectPreferentialVote(List(0,1,4)), sharedPubKey).get

    val votersBallots2 =
      for (_ <- 0 until numberOfVoters) yield
        PreferentialVoterBallot.createBallot(preferentialContext, DirectPreferentialVote(List(2,7,0)), sharedPubKey, stake).get

    (votersBallots ++ votersBallots2) -> expertsBallots
  }

  override def prepareUniDelegBallots(sharedPubKey: PubKey): (Seq[UniDelegVoterBallot], Seq[UniDelegExpertBallot]) = {
    val votersBallots =
      for (_ <- 0 until numberOfVoters) yield
        UniDelegPublicStakeBallot.createBallot(approvalContext, DelegatedUniDelegVote(1), sharedPubKey, stake).get

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield
        UniDelegExpertBallot.createBallot(approvalContext, expertId, DirectUniDelegVote(List.fill(5)(1)), sharedPubKey).get

    votersBallots -> expertsBallots
  }

  override def verify(tallyRes: List[(Int, Vector[BigInt])]): Boolean = Try {
    require(tallyRes.size == numberOfProposalsStage2)
    val stage1WinnerIds = List(0,2,1,7,4)
    tallyRes.zip(stage1WinnerIds).foreach { case (r, id) =>
      require(r._1 == id)
      require(r._2(0) == 0)
      require(r._2(1) == numberOfVoters * stake)
      require(r._2(2) == 0)
    }
  }.isSuccess
}
