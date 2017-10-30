package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.common.VotingSimulator

class BallotCreationPerformance extends FunSuite {
  test("benchmark ballot creation") {
    val numberOfExperts = (50 to 250).by(50)

    for (experts <- numberOfExperts) {
      val simulator = new VotingSimulator(experts, 1, 1, 1)

      println("Running test for " + experts + " experts ...")

      val ballot = Utils.time_ms("     Voter ballot creation: ", simulator.createVoterBallot(1, 1, 1, VoteCases.Yes)).asInstanceOf[VoterBallot]
      val ballotSize = ballot.uvChoice.foldLeft(0) {
        (acc, c) => acc + c._1.size + c._2.size
      } + ballot.uvDelegations.foldLeft(0) {
        (acc, c) => acc + c._1.size + c._2.size
      }
      println("     Voter ballot size: " + ballotSize + " bytes")

      val exballot = Utils.time_ms("     Expert ballot creation: ", simulator.createExpertBallot(1, 1, VoteCases.Yes)).asInstanceOf[ExpertBallot]
      val exballotSize = exballot.uvChoice.foldLeft(0) {
        (acc, c) => acc + c._1.size + c._2.size
      }
      println("     Expert ballot size: " + exballotSize + " bytes")
    }
  }

}
