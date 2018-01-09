package treasury.crypto.common

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.keygen.{C1, DecryptionManager}
import treasury.crypto.voting._
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}


class VotingSimulator(
  val numberOfCommitteeMembers: Int,
  val numberOfExperts: Int,
  val numberOfVoters: Int,
  val stakePerVoter: Int = 1,
  val withProofs: Boolean = false,
  sharedPubKey: Option[PubKey] = None
) {

  protected val cs = new Cryptosystem
  protected lazy val committeeMembers = Array.fill(numberOfCommitteeMembers)(cs.createKeyPair)
  protected val sharedPublicKey = sharedPubKey.getOrElse(
    committeeMembers.foldLeft(cs.infinityPoint)((sum,next) => sum.add(next._2)))

  def createVoterBallot(
    voterId: Int,
    projectId: Int,
    delegation: Int,
    choice: VoteCases.Value
  ): VoterBallot = {

    val voter = new RegularVoter(cs, numberOfExperts, sharedPublicKey, BigInteger.valueOf(stakePerVoter))
    if (delegation >= 0 && delegation < numberOfExperts)
      voter.produceDelegatedVote(projectId, delegation, withProofs)
    else
      voter.produceVote(projectId, choice, withProofs)
  }

  def createExpertBallot(expertId: Int, projectId: Int, choice: VoteCases.Value): ExpertBallot = {
    new Expert(cs, expertId, sharedPublicKey).produceVote(projectId, choice, withProofs)
  }

  def prepareExpertBallots(yes: Int, no: Int, abstain: Int): Seq[ExpertBallot] = {
    require((yes + no + abstain) == numberOfExperts)

    val yesBallots = for (expertId <- (0 until yes).par) yield {
      createExpertBallot(expertId, 0, VoteCases.Yes)
    }
    val noBallots = for (expertId <- (yes until no).par) yield {
      createExpertBallot(expertId, 0, VoteCases.No)
    }
    val abstainBallots = for (expertId <- (no until abstain).par) yield {
      createExpertBallot(expertId, 0, VoteCases.Abstain)
    }

    yesBallots.seq ++ noBallots.seq ++ abstainBallots.seq
  }

  def prepareVotersBallots(deleg: (Int, Int), yes: Int, no: Int, abstain: Int): Seq[VoterBallot] = {
    require((deleg._2 + yes + no + abstain) == numberOfVoters)
    require(deleg._1 >= 0 && deleg._1 < numberOfExperts)

    val delegBallots = for (voterId <- (0 until deleg._2).par) yield {
      createVoterBallot(voterId, 0, deleg._1, VoteCases.Yes)
    }
    val yesBallots = for (voterId <- (0 until yes).par) yield {
      createVoterBallot(voterId, 0, -1, VoteCases.Yes)
    }
    val noBallots = for (voterId <- (yes until no).par) yield {
      createVoterBallot(voterId, 0, -1, VoteCases.No)
    }
    val abstainBallots = for (voterId <- (no until abstain).par) yield {
      createVoterBallot(voterId, 0, -1, VoteCases.Abstain)
    }

    delegBallots.seq ++ yesBallots.seq ++ noBallots.seq ++ abstainBallots.seq
  }

  def prepareBallots(): Seq[Ballot] = {
    val delegations = numberOfVoters / 2

    val expertsBallots = prepareExpertBallots(0, numberOfExperts, 0)
    val votersBallots = prepareVotersBallots((1, delegations), numberOfVoters-delegations, 0, 0)

    expertsBallots.seq ++ votersBallots.seq
  }

  def prepareDecryptionShares(ballots: Seq[Ballot]): Seq[(C1, C1)] = {
    val managers = committeeMembers.map(m => new DecryptionManager(cs, 0, m, Array[BigInteger](), ballots))
    val delegationsC1 = managers.map(_.decryptC1ForDelegations())
    val choicesC1 = managers.map(_.decryptC1ForChoices(delegationsC1))

    delegationsC1.zip(choicesC1)
  }

  /* Consumes a list of ballots and decryption shares.
   * Returns tally results */
  def doTally(
    ballots: Seq[Ballot],
    decryptionShares: Seq[(C1, C1)]
  ): Tally.Result = {

    require(decryptionShares.size == numberOfCommitteeMembers)
    Tally.countVotes(cs, ballots, decryptionShares.map(_._1), decryptionShares.map(_._2))
  }
}
