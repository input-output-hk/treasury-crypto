package io.iohk.protocol.voting_2_0.approval.ballot

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCrsLight, RncePublicKeyLight}
import io.iohk.protocol.voting_2_0.approval.{UnitVectorRnce, VoteOption, VotingParameters}
import io.iohk.protocol.voting_2_0.approval.UnitVectorRnce.buildEncryptedUv
import io.iohk.protocol.voting_2_0.approval.VoteOption.VoteOption

case class VoterBallot(id: Int, uvs_enc: Seq[UnitVectorRnce])
case class VoterVote(ExpertId: Option[Int], vote: Option[VoteOption])

object VoterBallot{
  private def getIndexInUv(vote: VoterVote, uv_size: Int): Int = {
    require(vote.ExpertId.isEmpty || vote.vote.isEmpty, "ExpertId of vote should be empty")
    require(vote.ExpertId.isDefined || vote.vote.isDefined, "ExpertId of vote should be defined")
    require(uv_size > VoteOption.optionsNum, "Insufficient size of UV")

    if(vote.ExpertId.isDefined){
      val expertId = vote.ExpertId.get
      require(expertId >= 0, "expertId can't be negative")
      require(expertId < uv_size - VoteOption.optionsNum, "expertId is too big")
      expertId
    } else {
      (uv_size - 1) - VoteOption.toInt(vote.vote.get) // subtracting from a maximal index value
    }
  }

  def create(params: VotingParameters, voterId: Int, votes: Seq[VoterVote], pubKey: RncePublicKeyLight, crs: RnceCrsLight): VoterBallot = {
    import params.cryptoContext.group

    require(votes.length == params.numberOfProposals, "Number of votes is inconsistent with number of projects")

    val uv_size = params.numberOfExperts + params.numberOfOptions
    val uvenc_rand = votes.map{ vote =>
      buildEncryptedUv(getIndexInUv(vote, uv_size), uv_size, pubKey, crs)
    }
    VoterBallot(voterId, uvenc_rand.map(_._1))
  }

  def sum(ballots: Seq[VoterBallot])
         (implicit group: DiscreteLogGroup): Seq[UnitVectorRnce] = {
    ballots.tail.foldLeft(ballots.head.uvs_enc)(
      (uvs_enc_sum, ballot) => UnitVectorRnce.sum(ballot.uvs_enc, uvs_enc_sum)
    )
  }

  // Gets (delegations, options) parts of each UV from the given list
  def getParts(params: VotingParameters, uvs_enc: Seq[UnitVectorRnce]): Seq[(UnitVectorRnce, UnitVectorRnce)] = {
    uvs_enc.foreach(uv => require(uv.units.length == uvs_enc.head.units.length)) // all UVs have the same length
    require(params.numberOfExperts + params.numberOfOptions == uvs_enc.head.units.length) // UV's length is a sum of numberOfExperts and numberOfOptions
    uvs_enc.map(uv =>
      (
        UnitVectorRnce(uv.units.take(params.numberOfExperts)), // delegations part
        UnitVectorRnce(uv.units.takeRight(params.numberOfOptions)) // options part
      )
    )
  }
}
