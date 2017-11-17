package treasury.crypto

import treasury.crypto.common.VotingSimulator
import treasury.crypto.core.{TimeUtils, VoteCases}

/* Benchmarking ballot creation */
class BallotCreationPerformance {

  def run() = {
    val numberOfExperts = (50 to 250).by(50)

    for (experts <- numberOfExperts) {
      val simulator = new VotingSimulator(1, experts, 1, 1, true)

      println("Running test for " + experts + " experts ...")

      TimeUtils.accurate_time("\tVoter ballot creation: ", simulator.createVoterBallot(1, 1, 1, VoteCases.Yes))

      val ballot = simulator.createVoterBallot(1, 1, 1, VoteCases.Yes)
      val ballotSize = ballot.getUnitVector.foldLeft(0) {
        (acc, c) => acc + c._1.getEncoded(true).size + c._2.getEncoded(true).size
      }

      println("\tVoter ballot size: " + ballotSize + " bytes")
      println("\tVoter ballot proof size: " + ballot.proof.size + " bytes")

      TimeUtils.accurate_time("\tExpert ballot creation: ", simulator.createExpertBallot(1, 1, VoteCases.Yes))

      val exballot = simulator.createExpertBallot(1, 1, VoteCases.Yes)
      val exballotSize = exballot.getUnitVector.foldLeft(0) {
        (acc, c) => acc + c._1.getEncoded(true).size + c._2.getEncoded(true).size
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
