package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.common.VotingSimulator

/* Benchmarking ballot creation */
class BallotCreationPerformance extends FunSuite {

  def run() = {
    val numberOfExperts = (50 to 250).by(50)

    for (experts <- numberOfExperts) {
      val simulator = new VotingSimulator(experts, 1, 1, 1)

      println("Running test for " + experts + " experts ...")

      TimeUtils.accurate_time("\tVoter ballot creation: ", simulator.createVoterBallot(1, 1, 1, VoteCases.Yes))

      val ballot = simulator.createVoterBallot(1, 1, 1, VoteCases.Yes)
      val ballotSize = ballot.getUnitVector.foldLeft(0) {
        (acc, c) => acc + c._1.getEncoded(true).size + c._2.getEncoded(true).size
      }
      println("\tVoter ballot size: " + ballotSize + " bytes")

      TimeUtils.accurate_time("\tExpert ballot creation: ", simulator.createExpertBallot(1, 1, VoteCases.Yes))

      val exballot = simulator.createExpertBallot(1, 1, VoteCases.Yes)
      val exballotSize = exballot.getUnitVector.foldLeft(0) {
        (acc, c) => acc + c._1.getEncoded(true).size + c._2.getEncoded(true).size
      }
      println("\tExpert ballot size: " + exballotSize + " bytes")
    }
  }
}

object BallotCreationPerformance {
  def main(args: Array[String]) {
    new BallotCreationPerformance().run
  }
}
