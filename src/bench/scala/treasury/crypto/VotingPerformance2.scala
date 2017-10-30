package treasury.crypto

import treasury.crypto.common.VotingSimulator

/* Benchmarking tally for different number of experts */
class VotingPerformance2 extends {

  def run() = {
    val numberOfExperts = (50 to 250).by(50)
    val numberOfVoters = 1000

    for (experts <- numberOfExperts) {
      println("Running test for " + numberOfVoters + " voters and " + experts + " experts ...")

      val simulator = new VotingSimulator(experts, numberOfVoters, 1, 1)

      val ballots = TimeUtils.time("\tBallots creation: ", simulator.prepareBallots())

      TimeUtils.time("\tTally: ", simulator.doTally(ballots))
    }
  }
}

object VotingPerformance2 {
  def main(args: Array[String]) {
    new VotingPerformance2().run
  }
}