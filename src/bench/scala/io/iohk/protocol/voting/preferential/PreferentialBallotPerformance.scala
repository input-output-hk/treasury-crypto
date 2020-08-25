package io.iohk.protocol.voting.preferential

import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.CryptoContext

class PreferentialBallotPerformance {
  val ctx = new CryptoContext(None)
  val pubKey = ctx.group.createRandomGroupElement.get

  def run() = {
    val numberOfExperts = List(0)//(50 to 250).by(50)
    val numberOfProposals = List(10)//(50 to 250).by(50)
    val numberOfRankedProposals = List(10)//(10 to 50).by(10)

    for (experts <- numberOfExperts) {
      for (proposals <- numberOfProposals) {
        for (rankedProposals <- numberOfRankedProposals) {
          println("Running test for:")
          println("\tNumber of experts: " + experts)
          println("\tNumber of proposals: " + proposals)
          println("\tNumber of ranked proposals: " + rankedProposals)

          val pctx = new PreferentialContext(ctx, proposals, rankedProposals, experts)
          val vote = (0 until rankedProposals).toList

          val ballot = TimeUtils.time("\tVoter ballot creation: ", PreferentialVoterBallot.createBallot(pctx, DirectPreferentialVote(vote), pubKey, 1).get)

          //val ballot = PreferentialVoterBallot.createBallot(pctx, DelegatedPreferentialVote(0), pubKey, 1).get
          val ballotSize = ballot.bytes.size

          println("\tVoter ballot size: " + ballotSize + " bytes")

//          val exballot = TimeUtils.time("\tExpert ballot creation: ", PreferentialExpertBallot.createBallot(pctx, 0, DirectPreferentialVote(vote), pubKey).get)
//
//          //val exballot = PreferentialExpertBallot.createBallot(pctx, 0, DirectPreferentialVote(vote), pubKey).get
//          val exballotSize = exballot.bytes.size
//          println("\tExpert ballot size: " + exballotSize + " bytes")
        }
      }
    }
  }
}

object PreferentialBallotPerformance {
  def main(args: Array[String]) {
    new PreferentialBallotPerformance().run
  }
}
