package io.iohk.protocol.voting.approval.uni_delegation

import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.ApprovalContext

class UniDelegBallotPerformance {
  val ctx = new CryptoContext(None)
  val pubKey = ctx.group.createRandomGroupElement.get

  def run() = {
    val numberOfExperts = List(50)
    val numberOfProposals = (10 to 100).by(10)
    val numberOfChoices = 3

    for (experts <- numberOfExperts) {
      for (proposals <- numberOfProposals) {
        println("Running test for:")
        println("\tNumber of experts: " + experts)
        println("\tNumber of proposals: " + proposals)

        val pctx = new ApprovalContext(ctx, numberOfChoices, experts, proposals)
        val vote = List.fill(proposals)(0)

        val ballot = TimeUtils.time("\tVoter ballot creation: ", UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(vote), pubKey, 1).get)

        //val ballot = UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(vote), pubKey, 1).get
        val ballotSize = ballot.bytes.size

        println("\tVoter ballot size: " + ballotSize + " bytes")

        if (experts > 0) {
          val exballot = TimeUtils.time("\tExpert ballot creation: ", UniDelegExpertBallot.createBallot(pctx, 0, DirectUniDelegVote(vote), pubKey).get)

          //val exballot = UniDelegExpertBallot.createBallot(pctx, 0, DirectUniDelegVote(vote), pubKey).get
          val exballotSize = exballot.bytes.size
          println("\tExpert ballot size: " + exballotSize + " bytes")
        }
      }
    }
  }
}

object UniDelegBallotPerformance {
  def main(args: Array[String]) {
    new UniDelegBallotPerformance().run
  }
}