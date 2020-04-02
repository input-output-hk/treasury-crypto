package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.ballots.{ExpertBallot, VoterBallot}

import scala.util.Try


class BallotsSummator(ctx: CryptoContext,
                      numberOfExperts: Int) {
  import ctx.group

  private val neutralCiphertext = ElGamalCiphertext(group.groupIdentity, group.groupIdentity)

  case class UnitVectorSum(
    uvDelegations: Array[ElGamalCiphertext] = Array.fill[ElGamalCiphertext](numberOfExperts)(neutralCiphertext),
    uvChoices: Array[ElGamalCiphertext] = Array.fill[ElGamalCiphertext](VotingOptions.values.size)(neutralCiphertext)
  )

  /*
   * Maps proposal id to the summed encrypted unit vector
   */
  private var unitVectorSums: Map[Int, UnitVectorSum] = Map()

  def addVoterBallot(ballot: VoterBallot): Try[BallotsSummator] = Try {
    require(ballot.uvDelegations.length == numberOfExperts, "Invalid voter ballot: invalid number of delegation bits in the unit vector")
    require(ballot.uvChoice.length == VotingOptions.values.size, "Invalid voter ballot: invalid number of choice bits in the unit vector")
    require(ballot.stake > 0, "Invalid voter ballot: inconsistent stake")

    val unitVector = unitVectorSums.getOrElse(ballot.proposalId, UnitVectorSum())

    for(i <- unitVector.uvDelegations.indices) {
      val weightedVote = ballot.uvDelegations(i).pow(ballot.stake).get
      unitVector.uvDelegations(i) = unitVector.uvDelegations(i).multiply(weightedVote).get
    }
    for(i <- unitVector.uvChoices.indices) {
      val weightedVote = ballot.uvChoice(i).pow(ballot.stake).get
      unitVector.uvChoices(i) = unitVector.uvChoices(i).multiply(weightedVote).get
    }

    unitVectorSums = unitVectorSums + (ballot.proposalId -> unitVector)
    this
  }

  def addExpertBallot(ballot: ExpertBallot, delegatedVotingPower: BigInt): Try[BallotsSummator] = Try {
    require(ballot.uvChoice.length == VotingOptions.values.size, "Invalid expert ballot: invalid number of choice bits in the unit vector")
    require(delegatedVotingPower > 0, "Invalid expert ballot: inconsistent voting power")

    val unitVector = unitVectorSums.getOrElse(ballot.proposalId, UnitVectorSum())

    for(i <- unitVector.uvChoices.indices) {
      val weightedVote = ballot.uvChoice(i).pow(delegatedVotingPower).get
      unitVector.uvChoices(i) = unitVector.uvChoices(i).multiply(weightedVote).get
    }

    unitVectorSums = unitVectorSums + (ballot.proposalId -> unitVector)
    this
  }

  /**
    * Returns a map of summed up encrypted unit vectors from voter's and expert's ballots for different proposals.
    *
    * @return a map (proposalId -> UnitVectorSum)
    */
  def getSummedUnitVectors: Map[Int, UnitVectorSum] = unitVectorSums
}
