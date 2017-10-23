package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.common.VotingSimulator

class VotingPerformance2 extends FunSuite {

  test("benchmark tally for different number of experts") {
    val numberOfExperts = (50 to 250).by(50)
    val numberOfVoters = 1000

    for (experts <- numberOfExperts) {
      println("Running test for " + numberOfVoters + " voters and " + experts + " experts ...")

      val simulator = new VotingSimulator(experts, numberOfVoters, 1, 1)

      val ballots = Utils.time("     Ballots creation: ", simulator.prepareBallots())

      Utils.time("     Tally: ", simulator.doTally(ballots))
    }
  }
}

