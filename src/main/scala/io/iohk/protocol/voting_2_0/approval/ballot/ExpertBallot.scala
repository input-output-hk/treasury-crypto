package io.iohk.protocol.voting_2_0.approval.ballot

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCrsLight, RncePublicKeyLight}
import io.iohk.protocol.voting_2_0.approval.{UnitVectorRnce, VoteOption, VotingParameters}
import io.iohk.protocol.voting_2_0.approval.UnitVectorRnce.buildEncryptedUv
import io.iohk.protocol.voting_2_0.approval.VoteOption.VoteOption

case class ExpertBallot(id: Int, uvs_enc: Seq[UnitVectorRnce]){
  def weighted(weighting_coeffs: Seq[Int])
              (implicit group: DiscreteLogGroup): ExpertBallot = {
    require(weighting_coeffs.length == uvs_enc.length, "Number of weighting coefficients is inconsistent with number of proposals")
    ExpertBallot(
      id,
      (uvs_enc, weighting_coeffs).zipped.map(
        (uv, w) => uv * Array.fill(uv.units.length)(w)
      )
    )
  }
}
case class ExpertVote(vote: VoteOption)

object ExpertBallot{
  private def getIndexInUv(vote: ExpertVote, uv_size: Int): Int = {
    require(uv_size == VoteOption.optionsNum, "Incorrect size of UV")
    (uv_size - 1) - VoteOption.toInt(vote.vote) // subtracting from a maximal index value
  }

  def create(params: VotingParameters, expertId: Int, votes: Seq[ExpertVote], pubKey: RncePublicKeyLight, crs: RnceCrsLight): ExpertBallot = {
    import params.cryptoContext.group

    require(votes.length == params.numberOfProposals, "Number of votes is inconsistent with number of projects")

    val uv_size = params.numberOfOptions
    val uvenc_rand = votes.map{ vote =>
      buildEncryptedUv(getIndexInUv(vote, uv_size), uv_size, pubKey, crs)
    }
    ExpertBallot(expertId, uvenc_rand.map(_._1))
  }

  def sum(ballots: Seq[ExpertBallot])
         (implicit group: DiscreteLogGroup): Seq[UnitVectorRnce] = {
    ballots.tail.foldLeft(ballots.head.uvs_enc)(
      (uvs_enc_sum, ballot) => UnitVectorRnce.sum(ballot.uvs_enc, uvs_enc_sum)
    )
  }
}