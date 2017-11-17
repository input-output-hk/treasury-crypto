package treasury.crypto

import treasury.crypto.common.VotingSimulator
import treasury.crypto.core.TimeUtils

/* Benchmarking tally for different number of voters */
class VotingPerformance1 {

  def run() = {
    val numberOfCommitteeMembers = 5
    val numberOfVoters = (1000 to 5000).by(1000)
    val numberOfExperts = 50

    for (voters <- numberOfVoters) {
      println("Running test for " + voters + " voters and " + numberOfExperts + " experts ...")

      val simulator = new VotingSimulator(numberOfCommitteeMembers, numberOfExperts, voters)

      val ballots = TimeUtils.time("\tBallots creation: ", simulator.prepareBallots())
      val decryptionShares = TimeUtils.time("\tDecryption shares creation: ", simulator.prepareDecryptionShares(ballots))

      TimeUtils.time("\tTally: ", simulator.doTally(ballots, decryptionShares))
    }
  }
}

object VotingPerformance1 {
  def main(args: Array[String]) {
    new VotingPerformance1().run
  }
}
