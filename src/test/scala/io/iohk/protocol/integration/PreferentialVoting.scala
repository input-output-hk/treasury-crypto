package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.CommitteeMember
import io.iohk.protocol.voting.preferential.tally.{PreferentialBallotsSummator, PreferentialTally}
import io.iohk.protocol.voting.preferential._

import scala.util.Try

abstract class PreferentialVoting(ctx: CryptoContext) extends VotingSimulator {
  import PreferentialVoting.PreferentialTallySimulator
  override type RESULT = PreferentialTally#RESULT

  def prepareBallots(sharedPubKey: PubKey): (Seq[PreferentialVoterBallot], Seq[PreferentialExpertBallot])
  def context: PreferentialContext

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
    val ballotsSummator = new PreferentialBallotsSummator(context)
    voterBallots.foreach(ballotsSummator.addVoterBallot(_))

    val tally = new PreferentialTally(context, committeeMembers.head.memberIdentifier, dkgViolators)
    val tallySimulator = new PreferentialTallySimulator(context, tally, ballotsSummator, expertBallots)
    tallySimulator.runTally(committeeMembers.head.memberIdentifier, committeeMembers, dkgR1Data).get
  }
}

object PreferentialVoting {
  class PreferentialTallySimulator(override val pctx: PreferentialContext,
                                   override val tally: PreferentialTally,
                                   override val summator: PreferentialBallotsSummator,
                                   override val expertBallots: Seq[PreferentialExpertBallot]) extends TallySimulator {
    override type TALLY = PreferentialTally
    override type PCTX = PreferentialContext
  }
}

class PreferentialVotingScenario1(ctx: CryptoContext) extends PreferentialVoting(ctx) {
  private val numberOfProposals = 5
  private val numberOfRankedProposals = 3
  private val numberOfVoters = 7
  private val numberOfExperts = 3
  private val stake = 57

  override val context = new PreferentialContext(ctx, numberOfProposals, numberOfRankedProposals, numberOfExperts)

  def prepareBallots(sharedPubKey: PubKey): (Seq[PreferentialVoterBallot], Seq[PreferentialExpertBallot]) = {
    val votersBallots =
      for (_ <- 0 until numberOfVoters) yield
        PreferentialVoterBallot.createBallot(context, DelegatedPreferentialVote(numberOfVoters % numberOfExperts), sharedPubKey, stake).get

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield
        PreferentialExpertBallot.createBallot(context, expertId, DirectPreferentialVote(List(0,1,4)), sharedPubKey).get

    votersBallots -> expertsBallots
  }

  override def verify(tallyRes: List[BigInt]): Boolean = Try {
    require(tallyRes.size == 5)
    require(tallyRes(0) == numberOfVoters * stake * 3)
    require(tallyRes(1) == numberOfVoters * stake * 2)
    require(tallyRes(4) == numberOfVoters * stake * 1)
    require(tallyRes(2) == 0)
    require(tallyRes(3) == 0)
  }.isSuccess
}

class PreferentialVotingScenario2(ctx: CryptoContext) extends PreferentialVoting(ctx) {
  private val numberOfProposals = 10
  private val numberOfRankedProposals = 4
  private val numberOfVoters = 7
  private val numberOfExperts = 3
  private val stake = 13

  override val context = new PreferentialContext(ctx, numberOfProposals, numberOfRankedProposals, numberOfExperts)

  def prepareBallots(sharedPubKey: PubKey): (Seq[PreferentialVoterBallot], Seq[PreferentialExpertBallot]) = {
    val votersBallots1 =
      for (_ <- 0 until numberOfVoters) yield
        PreferentialVoterBallot.createBallot(context, DelegatedPreferentialVote(numberOfVoters % numberOfExperts), sharedPubKey, stake).get

    val votersBallots2 = List(
      PreferentialVoterBallot.createBallot(context, DirectPreferentialVote(List(1,5,9,2)), sharedPubKey, stake).get,
      PreferentialVoterBallot.createBallot(context, DirectPreferentialVote(List(5,2,0,1)), sharedPubKey, stake).get,
      PreferentialVoterBallot.createBallot(context, DirectPreferentialVote(List(4,3,0,1)), sharedPubKey, stake).get)

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield
        PreferentialExpertBallot.createBallot(context, expertId, DirectPreferentialVote(List(9,8,1,0)), sharedPubKey).get

    (votersBallots1 ++ votersBallots2) -> expertsBallots
  }

  override def verify(tallyRes: List[BigInt]): Boolean = Try {
    require(tallyRes.size == 10)
    require(tallyRes(0) == 11 * stake)
    require(tallyRes(1) == 20 * stake)
    require(tallyRes(2) == 4 * stake)
    require(tallyRes(3) == 3 * stake)
    require(tallyRes(4) == 4 * stake)
    require(tallyRes(5) == 7 * stake)
    require(tallyRes(6) == 0)
    require(tallyRes(7) == 0)
    require(tallyRes(8) == 21 * stake)
    require(tallyRes(9) == 30 * stake)
  }.isSuccess
}