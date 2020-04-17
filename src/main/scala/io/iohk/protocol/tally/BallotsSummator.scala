package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.VotingOptions
import io.iohk.protocol.voting.ballots.{ExpertBallot, VoterBallot}

import scala.util.Try

/**
  * BallotsSummator is used to sum up ballots for their further processing. It is convenient to sum up
  * ballots one by one instead of accumulating them in memory and sum up all at once.
  *
  * @param ctx
  * @param numberOfExperts
  */
class BallotsSummator(ctx: CryptoContext,
                      numberOfExperts: Int) {
  import ctx.group

  private val neutralCiphertext = ElGamalCiphertext(group.groupIdentity, group.groupIdentity)

  /*
   * Maps proposal id to the summed encrypted unit vector
   */
  private var delegationsSums: Map[Int, Vector[ElGamalCiphertext]] = Map()
  private var choicesSums: Map[Int, Vector[ElGamalCiphertext]] = Map()

  def addVoterBallot(ballot: VoterBallot): Try[BallotsSummator] = Try {
    require(ballot.uvDelegations.length == numberOfExperts, "Invalid voter ballot: invalid number of delegation bits in the unit vector")
    require(ballot.uvChoice.length == VotingOptions.values.size, "Invalid voter ballot: invalid number of choice bits in the unit vector")
    require(ballot.stake > 0, "Invalid voter ballot: inconsistent stake")

    val delegationsUnitVector = delegationsSums.getOrElse(ballot.proposalId,
      Vector.fill[ElGamalCiphertext](numberOfExperts)(neutralCiphertext))
    val choicesUnitVector = choicesSums.getOrElse(ballot.proposalId,
      Vector.fill[ElGamalCiphertext](VotingOptions.values.size)(neutralCiphertext))

    val updatedDelegationsVector = for(i <- delegationsUnitVector.indices.toVector) yield {
      val weightedVote = ballot.uvDelegations(i).pow(ballot.stake).get
      delegationsUnitVector(i).multiply(weightedVote).get
    }
    val updatedChoicesVector = for(i <- choicesUnitVector.indices.toVector) yield {
      val weightedVote = ballot.uvChoice(i).pow(ballot.stake).get
      choicesUnitVector(i).multiply(weightedVote).get
    }

    delegationsSums = delegationsSums + (ballot.proposalId -> updatedDelegationsVector)
    choicesSums = choicesSums + (ballot.proposalId -> updatedChoicesVector)
    this
  }
  
  def addExpertBallot(ballot: ExpertBallot, delegatedVotingPower: BigInt): Try[BallotsSummator] = Try {
    require(ballot.uvChoice.length == VotingOptions.values.size, "Invalid expert ballot: invalid number of choice bits in the unit vector")
    require(delegatedVotingPower > 0, "Invalid expert ballot: inconsistent voting power")

    val choicesUnitVector = choicesSums.getOrElse(ballot.proposalId,
      Vector.fill[ElGamalCiphertext](VotingOptions.values.size)(neutralCiphertext))

    val updatedChoicesVector = for(i <- choicesUnitVector.indices.toVector) yield {
      val weightedVote = ballot.uvChoice(i).pow(delegatedVotingPower).get
      choicesUnitVector(i).multiply(weightedVote).get
    }

    choicesSums = choicesSums + (ballot.proposalId -> updatedChoicesVector)
    this
  }

  /**
    * Returns a map of summed up encrypted unit vectors from voter's and expert's ballots for different proposals.
    */
  def getDelegationsSum: Map[Int, Vector[ElGamalCiphertext]] = delegationsSums
  def getChoicesSum: Map[Int, Vector[ElGamalCiphertext]] = choicesSums
}
