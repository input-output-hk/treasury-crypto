package io.iohk.protocol.voting_2_0.approval

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.voting_2_0.approval.ballot.{ExpertBallot, VoterBallot}

case class ResultsPhase1(delegations_sum: Seq[UnitVectorRnce],
                         votes_sum:       Seq[UnitVectorRnce])

case class ResultsPhase2(votes_total_sum: Seq[UnitVectorRnce])

object Tally{
  def phase1(ballots: Seq[VoterBallot],
             params: VotingParameters)
            (implicit group: DiscreteLogGroup): ResultsPhase1 = {
    val sum = VoterBallot.getParts(params, VoterBallot.sum(ballots))
    ResultsPhase1(
      delegations_sum = sum.map(_._1),
      votes_sum = sum.map(_._2)
    )
  }

  def phase2(ballots: Seq[ExpertBallot],
             opened_delegations: Seq[Seq[Int]],
             votes_sum: Seq[UnitVectorRnce])
            (implicit group: DiscreteLogGroup): ResultsPhase2 = {
    val experts_sum = ExpertBallot.sum(weighExperts(ballots, opened_delegations))(group)
    ResultsPhase2(UnitVectorRnce.sum(votes_sum, experts_sum))
  }

  private def weighExperts(ballots: Seq[ExpertBallot],
                           opened_delegations: Seq[Seq[Int]])
                          (implicit group: DiscreteLogGroup): Seq[ExpertBallot] = {
    opened_delegations.transpose.zipWithIndex.flatMap{
      case (expertWeights, i) =>
        ballots.find(_.id == i) match {
          case Some(expertBallot) => Some(expertBallot.weighted(expertWeights))
          case _ => None
        }
    }
  }
}
