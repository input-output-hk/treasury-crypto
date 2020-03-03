package treasury.crypto

import treasury.crypto.common.VotingSimulator
import treasury.crypto.core.TimeUtils
import treasury.crypto.voting.VotingOptions

/* Benchmarking ballot creation */
class BallotCreationPerformance {

  def run() = {
    val numberOfExperts = (50 to 250).by(50)

    for (experts <- numberOfExperts) {
      val simulator = new VotingSimulator(1, experts, 1, 1, true)

      println("Running test for " + experts + " experts ...")

      TimeUtils.accurate_time("\tVoter ballot creation: ", simulator.createVoterBallot(1, 1, 1, VotingOptions.Yes))

      val ballot = simulator.createVoterBallot(1, 1, 1, VotingOptions.Yes)
      val ballotSize = ballot.unitVector.foldLeft(0) {
        (acc, c) => acc + c.bytes.size
      }

      println("\tVoter ballot size: " + ballotSize + " bytes")
      println("\tVoter ballot proof size: " + ballot.proof.size + " bytes")

      TimeUtils.accurate_time("\tExpert ballot creation: ", simulator.createExpertBallot(1, 1, VotingOptions.Yes))

      val exballot = simulator.createExpertBallot(1, 1, VotingOptions.Yes)
      val exballotSize = exballot.unitVector.foldLeft(0) {
        (acc, c) => acc + c.bytes.size
      }
      println("\tExpert ballot size: " + exballotSize + " bytes")
      println("\tExpert ballot proof size: " + exballot.proof.size + " bytes")
    }
  }
}

object BallotCreationPerformance {
  def main(args: Array[String]) {
    new BallotCreationPerformance().run
  }
}
