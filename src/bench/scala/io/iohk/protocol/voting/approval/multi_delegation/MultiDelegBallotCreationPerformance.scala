package io.iohk.protocol.voting.approval.multi_delegation

import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.ApprovalContext

/* Benchmarking ballot creation */
class MultiDelegBallotCreationPerformance {

  val ctx = new CryptoContext(None)
  val pubKey = ctx.group.createRandomGroupElement.get

  def run() = {
    val numberOfExperts = (50 to 250).by(50)

    for (experts <- numberOfExperts) {
      println("Running test for " + experts + " experts ...")

      val pctx = new ApprovalContext(ctx, 3, experts, 1)

      TimeUtils.accurate_time("\tVoter ballot creation: ", MultiDelegPublicStakeBallot.createBallot(pctx,0, DelegatedMultiDelegVote(0),pubKey,1).get)

      val ballot = MultiDelegPublicStakeBallot.createBallot(pctx,0, DelegatedMultiDelegVote(0), pubKey,1).get
      val ballotSize = ballot.bytes.size

      println("\tVoter ballot size: " + ballotSize + " bytes")
      println("\tVoter ballot proof size: " + ballot.uProof.get.size + " bytes")

      TimeUtils.accurate_time("\tExpert ballot creation: ", MultiDelegExpertBallot.createBallot(pctx, 0, 0, DirectMultiDelegVote(0), pubKey).get)

      val exballot = MultiDelegExpertBallot.createBallot(pctx, 0, 0, DirectMultiDelegVote(0), pubKey).get
      val exballotSize = exballot.bytes.size
      println("\tExpert ballot size: " + exballotSize + " bytes")
      println("\tExpert ballot proof size: " + exballot.uProof.get.size + " bytes")
    }
  }
}

object MultiDelegBallotCreationPerformance {
  def main(args: Array[String]) {
    new MultiDelegBallotCreationPerformance().run
  }
}
