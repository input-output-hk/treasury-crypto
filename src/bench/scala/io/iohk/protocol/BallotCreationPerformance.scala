package io.iohk.protocol

import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.voting.{Expert, RegularVoter, VotingOptions}

/* Benchmarking ballot creation */
class BallotCreationPerformance {

  val ctx = new CryptoContext(None)
  val pubKey = ctx.group.createRandomGroupElement.get

  def run() = {
    val numberOfExperts = (50 to 250).by(50)

    for (experts <- numberOfExperts) {
      println("Running test for " + experts + " experts ...")

      val voter = new RegularVoter(ctx, experts, pubKey, 1)
      val expert = new Expert(ctx, 0, pubKey)

      TimeUtils.accurate_time("\tVoter ballot creation: ", voter.produceVote(0, VotingOptions.Yes))

      val ballot = voter.produceVote(0, VotingOptions.Yes)
      val ballotSize = ballot.unitVector.foldLeft(0) {
        (acc, c) => acc + c.bytes.size
      }

      println("\tVoter ballot size: " + ballotSize + " bytes")
      println("\tVoter ballot proof size: " + ballot.proof.size + " bytes")

      TimeUtils.accurate_time("\tExpert ballot creation: ", expert.produceVote(0, VotingOptions.Yes))

      val exballot = expert.produceVote(0, VotingOptions.Yes)
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
