package io.iohk.common

import java.math.BigInteger

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.Cryptosystem
import io.iohk.protocol.decryption.DecryptionManager
import io.iohk.protocol.keygen.datastructures.C1Share
import io.iohk.protocol.voting.Tally.Result
import io.iohk.protocol.voting._
import io.iohk.protocol.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.util.Try


class VotingSimulator(
  val numberOfCommitteeMembers: Int,
  val numberOfExperts: Int,
  val numberOfVoters: Int,
  val stakePerVoter: Int = 1,
  val withProofs: Boolean = false,
  sharedPubKey: Option[PubKey] = None
) {

  val cs = new Cryptosystem
  import cs.{group, hash}

  protected lazy val committeeMembers = Array.fill(numberOfCommitteeMembers)(cs.createKeyPair)
  protected val sharedPublicKey = sharedPubKey.getOrElse(
    committeeMembers.foldLeft(cs.infinityPoint)((sum,next) => sum.multiply(next._2).get))

  def createVoterBallot(
    voterId: Int,
    projectId: Int,
    delegation: Int,
    choice: VotingOptions.Value
  ): VoterBallot = {

    val voter = new RegularVoter(cs, numberOfExperts, sharedPublicKey, BigInteger.valueOf(stakePerVoter))
    if (delegation >= 0 && delegation < numberOfExperts)
      voter.produceDelegatedVote(projectId, delegation, withProofs)
    else
      voter.produceVote(projectId, choice, withProofs)
  }

  def createExpertBallot(expertId: Int, projectId: Int, choice: VotingOptions.Value): ExpertBallot = {
    new Expert(cs, expertId, sharedPublicKey).produceVote(projectId, choice, withProofs)
  }

  def prepareExpertBallots(yes: Int, no: Int, abstain: Int): Seq[ExpertBallot] = {
    require((yes + no + abstain) == numberOfExperts)

    val yesBallots = for (expertId <- (0 until yes).par) yield {
      createExpertBallot(expertId, 0, VotingOptions.Yes)
    }
    val noBallots = for (expertId <- (yes until no).par) yield {
      createExpertBallot(expertId, 0, VotingOptions.No)
    }
    val abstainBallots = for (expertId <- (no until abstain).par) yield {
      createExpertBallot(expertId, 0, VotingOptions.Abstain)
    }

    yesBallots.seq ++ noBallots.seq ++ abstainBallots.seq
  }

  def prepareVotersBallots(deleg: (Int, Int), yes: Int, no: Int, abstain: Int): Seq[VoterBallot] = {
    require((deleg._2 + yes + no + abstain) == numberOfVoters)
    require(deleg._1 >= 0 && deleg._1 < numberOfExperts)

    val delegBallots = for (voterId <- (0 until deleg._2).par) yield {
      createVoterBallot(voterId, 0, deleg._1, VotingOptions.Yes)
    }
    val yesBallots = for (voterId <- (0 until yes).par) yield {
      createVoterBallot(voterId, 0, -1, VotingOptions.Yes)
    }
    val noBallots = for (voterId <- (yes until no).par) yield {
      createVoterBallot(voterId, 0, -1, VotingOptions.No)
    }
    val abstainBallots = for (voterId <- (no until abstain).par) yield {
      createVoterBallot(voterId, 0, -1, VotingOptions.Abstain)
    }

    delegBallots.seq ++ yesBallots.seq ++ noBallots.seq ++ abstainBallots.seq
  }

  def prepareBallots(): Seq[Ballot] = {
    val delegations = numberOfVoters / 2

    val expertsBallots = prepareExpertBallots(0, numberOfExperts, 0)
    val votersBallots = prepareVotersBallots((1, delegations), numberOfVoters-delegations, 0, 0)

    expertsBallots.seq ++ votersBallots.seq
  }

  def prepareDecryptionShares(ballots: Seq[Ballot]): Seq[((PubKey, C1Share), (PubKey, C1Share))] = {
    val manager = new DecryptionManager(cs, ballots)
    val delegationsC1 = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i)._2, manager.decryptC1ForDelegations(i, 0, committeeMembers(i)._1))
    }

    val delegations = manager.computeDelegations(delegationsC1.map(_._2.decryptedC1.map(_._1)))

    val choicesC1 = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i)._2, manager.decryptC1ForChoices(i, 0, committeeMembers(i)._1, delegations))
    }

    delegationsC1.zip(choicesC1)
  }

  def verifyDecryptionShares(ballots: Seq[Ballot], decryptionShares: Seq[((PubKey, C1Share), (PubKey, C1Share))]): Boolean = Try {
    val validator = new DecryptionManager(cs, ballots)

    val delegationsC1 = decryptionShares.map(_._1)
    val choicesC1 = decryptionShares.map(_._2)

    val delegations = validator.computeDelegations(delegationsC1.map(_._2.decryptedC1.map(_._1)))

    val failedDeleg = delegationsC1.exists(c => !validator.validateDelegationsC1(c._1, c._2).isSuccess)
    val failedChoices = choicesC1.exists(c => !validator.validateChoicesC1(c._1, c._2, delegations).isSuccess)

    !failedDeleg && !failedChoices
  }.isSuccess

  /* Consumes a list of ballots and decryption shares.
   * Returns tally results */
  def doTally(
    ballots: Seq[Ballot],
    decryptionShares: Seq[(C1Share, C1Share)]
  ): Result = {

    require(decryptionShares.size == numberOfCommitteeMembers)

    val d = new DecryptionManager(cs, ballots)
    val delegations = d.computeDelegations(decryptionShares.map(_._1.decryptedC1.map(_._1)))

    Tally.countVotes(cs, ballots, decryptionShares.map(_._2.decryptedC1.map(_._1)), delegations).get
  }
}
