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

      val pctx = new ProtocolContext(ctx, 3, experts)
      val voter = new RegularVoter(pctx, pubKey,1)
      val expert = new Expert(pctx,0, pubKey)

      TimeUtils.accurate_time("\tVoter ballot creation: ", voter.produceVote(0, VotingOptions.Yes))

      val ballot = voter.produceVote(0, VotingOptions.Yes)
      val ballotSize = ballot.bytes.size

      println("\tVoter ballot size: " + ballotSize + " bytes")
      println("\tVoter ballot proof size: " + ballot.uProof.size + " bytes")

      TimeUtils.accurate_time("\tExpert ballot creation: ", expert.produceVote(0, VotingOptions.Yes))

      val exballot = expert.produceVote(0, VotingOptions.Yes)
      val exballotSize = exballot.bytes
      println("\tExpert ballot size: " + exballotSize + " bytes")
      println("\tExpert ballot proof size: " + exballot.uProof.size + " bytes")
    }
  }
}

object BallotCreationPerformance {
  def main(args: Array[String]) {
    new BallotCreationPerformance().run
  }
}
