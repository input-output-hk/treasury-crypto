package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.voting.{ExpertBallot, VoterBallot}

import scala.util.Try

/**
  * BallotsSummator is used to sum up ballots for their further processing. The idea is to sum up
  * ballots one by one instead of accumulating them in memory and sum up all at once.
  *
  * @param ctx
  */
class BallotsSummator(ctx: ProtocolContext) {
  import ctx.cryptoContext.group

  private val neutralCiphertext = ElGamalCiphertext(group.groupIdentity, group.groupIdentity)

  /*
   * Maps proposal id to the summed encrypted unit vector
   */
  private var delegationsSums: Map[Int, Vector[ElGamalCiphertext]] = Map()
  private var choicesSums: Map[Int, Vector[ElGamalCiphertext]] = Map()

  def addVoterBallot(ballot: VoterBallot): Try[BallotsSummator] = Try {
    require(ballot.weightedUnitVector.delegations.length == ctx.numberOfExperts, "Invalid voter ballot: invalid number of delegation bits in the unit vector")
    require(ballot.weightedUnitVector.choice.length == ctx.numberOfChoices, "Invalid voter ballot: invalid number of choice bits in the unit vector")

    val delegationsUnitVector = delegationsSums.getOrElse(ballot.proposalId,
      Vector.fill[ElGamalCiphertext](ctx.numberOfExperts)(neutralCiphertext))
    val choicesUnitVector = choicesSums.getOrElse(ballot.proposalId,
      Vector.fill[ElGamalCiphertext](ctx.numberOfChoices)(neutralCiphertext))

    val updatedDelegationsVector = for(i <- delegationsUnitVector.indices.toVector) yield {
      val weightedVote = ballot.weightedUnitVector.delegations(i)
      delegationsUnitVector(i).multiply(weightedVote).get
    }
    val updatedChoicesVector = for(i <- choicesUnitVector.indices.toVector) yield {
      val weightedVote = ballot.weightedUnitVector.choice(i)
      choicesUnitVector(i).multiply(weightedVote).get
    }

    delegationsSums = delegationsSums + (ballot.proposalId -> updatedDelegationsVector)
    choicesSums = choicesSums + (ballot.proposalId -> updatedChoicesVector)
    this
  }
  
  def addExpertBallot(ballot: ExpertBallot, delegatedVotingPower: BigInt): Try[BallotsSummator] = Try {
    require(ballot.uChoiceVector.length == ctx.numberOfChoices, "Invalid expert ballot: invalid number of choice bits in the unit vector")
    require(delegatedVotingPower > 0, "Invalid expert ballot: inconsistent voting power")

    val choicesUnitVector = choicesSums.getOrElse(ballot.proposalId,
      Vector.fill[ElGamalCiphertext](ctx.numberOfChoices)(neutralCiphertext))

    val updatedChoicesVector = for(i <- choicesUnitVector.indices.toVector) yield {
      val weightedVote = ballot.uChoiceVector(i).pow(delegatedVotingPower).get
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
