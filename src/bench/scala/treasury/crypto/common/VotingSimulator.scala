package treasury.crypto.common

import treasury.crypto._


class VotingSimulator(val numberOfExperts: Int,
                      val numberOfVoters: Int,
                      val stakePerVoter: Int,
                      val numberOfProjects: Int) {

  protected val cs = new Cryptosystem
  protected val (privKey, pubKey) = cs.createKeyPair()

  def createVoterBallot(voterId: Int,
                        projectId: Int,
                        delegation: Int,
                        choice: VoteCases.Value): Ballot = {
    RegularVoter(cs, voterId, numberOfExperts, pubKey, BigInt(stakePerVoter).toByteArray)
      .produceVote(projectId, delegation, choice)
  }

  def createExpertBallot(expertId: Int, projectId: Int, choice: VoteCases.Value): Ballot = {
    Expert(cs, expertId, numberOfExperts, pubKey)
      .produceVote(projectId, -1, choice)
  }

  /* Returns a list of pairs for each project with project id and corresponding ballots */
  def prepareBallots(): Seq[(Int, Seq[Ballot])] = {
    for (projectId <- 0 until numberOfProjects) yield {
      (projectId, prepareBallots(projectId))
    }
  }

  def prepareBallots(projectId: Int): Seq[Ballot] = {
    val delegations = numberOfVoters / 2
    val votersIds = numberOfExperts until (numberOfExperts + delegations)
    val delegatedVotersIds = (numberOfExperts + delegations) until (numberOfExperts + numberOfVoters)

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield {
        createExpertBallot(expertId, projectId, VoteCases.No)
      }

    val votersBallots =
      for (id <- votersIds) yield {
        createVoterBallot(id, projectId, -1, VoteCases.Yes)
      }

    val votersDelegatedBallots =
      for (id <- delegatedVotersIds) yield {
        createVoterBallot(id, projectId, id % numberOfExperts, VoteCases.Yes)
      }

    expertsBallots ++ votersBallots ++ votersDelegatedBallots
  }

  /* Consumes a list of pairs with project id and ballots.
   * Returns a list of projects with tally results */
  def doTally(ballots: Seq[(Int, Seq[Ballot])]): Seq[(Int, TallyResult)] = {
    // Obtaining results by an arbitrary voter
    val voter = RegularVoter(cs, 0, numberOfExperts, pubKey, Array(1))

    ballots.map {
      project => (project._1, voter.tallyVotes(project._2, privKey))
    }
  }
}
