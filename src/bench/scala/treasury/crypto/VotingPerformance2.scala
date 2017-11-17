package treasury.crypto

import treasury.crypto.common.VotingSimulator
import treasury.crypto.core.TimeUtils

/* Benchmarking tally for different number of experts */
class VotingPerformance2 {

  def run() = {
    val numberOfCommitteeMembers = 5
    val numberOfExperts = (50 to 250).by(50)
    val numberOfVoters = 1000

    for (experts <- numberOfExperts) {
      println("Running test for " + numberOfVoters + " voters and " + experts + " experts ...")

      val simulator = new VotingSimulator(numberOfCommitteeMembers, experts, numberOfVoters)

      val ballots = TimeUtils.time("\tBallots creation: ", simulator.prepareBallots())
      val decryptionShares = TimeUtils.time("\tDecryption shares creation: ", simulator.prepareDecryptionShares(ballots))

      TimeUtils.time("\tTally: ", simulator.doTally(ballots, decryptionShares))
    }
  }
}

object VotingPerformance2 {
  def main(args: Array[String]) {
    new VotingPerformance2().run
  }
}