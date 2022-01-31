package io.iohk.protocol.voting_2_0.preferential

import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.CryptoContext

class PreferentialBallotPerformance {
  private val ctx = new CryptoContext(None)
  private val pubKey = ctx.group.createRandomGroupElement.get

  def run(): Unit = {
    val numberOfExperts = List(8, 20, 40, 80, 160) //(50 to 250).by(50)
    val numberOfAllProjects = List(8, 20, 40, 80, 160) //(50 to 250).by(50)
    val sizeOfProjectsShortlist = List(4, 8, 16) //(10 to 50).by(10)

    for (expertsNum <- numberOfExperts) {
      for (projectsNum <- numberOfAllProjects) {
        for (shortlistSize <- sizeOfProjectsShortlist) {
          println("--------------------------------------------")
          println("Experts, Projects, Shortlist: " + expertsNum + ", " + projectsNum + ", " + shortlistSize)
          println("--------------------------------------------")

          val params = VotingParameters(ctx, shortlistSize, projectsNum, expertsNum)
          val ranks = (0 until shortlistSize).toList

          val (voterBallot, _) = TimeUtils.get_time_average_s("Voter  ballot creation time and size: ",
            BallotVoter.cast(pubKey, params, Left(ranks)).get, 1
          )
          println((voterBallot.size.toFloat / 1024).ceil.toInt + " KB")

          if (expertsNum > 0) {
            val (expertBallot, _) = TimeUtils.get_time_average_s("Expert ballot creation time and size: ",
              BallotExpert.cast(pubKey, params, ranks).get, 1
            )
            println((expertBallot.size.toFloat / 1024).ceil.toInt + " KB")
          }
        }
      }
    }
  }
}

object PreferentialBallotPerformance {
  def main(args: Array[String]) {
    new PreferentialBallotPerformance().run()
  }
}
