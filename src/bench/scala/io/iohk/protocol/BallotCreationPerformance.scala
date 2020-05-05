package io.iohk.protocol

import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.voting.ballots.{ExpertBallot, PublicStakeBallot}
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

      TimeUtils.accurate_time("\tVoter ballot creation: ", PublicStakeBallot.createBallot(pctx,0,0,pubKey,1).get)

      val ballot = PublicStakeBallot.createBallot(pctx,0,0,pubKey,1).get
      val ballotSize = ballot.bytes.size

      println("\tVoter ballot size: " + ballotSize + " bytes")
      println("\tVoter ballot proof size: " + ballot.uProof.size + " bytes")

      TimeUtils.accurate_time("\tExpert ballot creation: ", ExpertBallot.createBallot(pctx, 0, 0, 0, pubKey).get)

      val exballot = ExpertBallot.createBallot(pctx, 0, 0, 0, pubKey).get
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
