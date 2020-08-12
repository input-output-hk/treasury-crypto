package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.UniDelegVoterBallot

import scala.util.Try

class UniDelegBallotsSummator(ctx: ApprovalContext) {
  import ctx.cryptoContext.group

  private val neutralCiphertext = ElGamalCiphertext(group.groupIdentity, group.groupIdentity)

  private var delegationsSum: Option[Vector[ElGamalCiphertext]] = None
  private var choicesSums: Option[List[Vector[ElGamalCiphertext]]] = None

  private def initChoicesSum: List[Vector[ElGamalCiphertext]] =
    (0 until ctx.numberOfProposals).map { _ =>
      Vector.fill[ElGamalCiphertext](ctx.numberOfChoices)(neutralCiphertext)
    }.toList
  private def initDelegationsSum = Vector.fill[ElGamalCiphertext](ctx.numberOfExperts)(neutralCiphertext)

  def addVoterBallot(ballot: UniDelegVoterBallot): Try[UniDelegBallotsSummator] = Try {
    val choicesVectors = ballot.weightedChoiceVectors
    val delegVector = ballot.weightedDelegationVector

    require(delegVector.length == ctx.numberOfExperts, "Invalid voter ballot: invalid number of delegation bits in the unit vector")
    require(choicesVectors.length == ctx.numberOfProposals, "Invalid voter ballot: invalid number of choices")
    choicesVectors.foreach(v =>
      require(v.length == ctx.numberOfChoices, "Invalid voter ballot: invalid number of choice bits in the unit vector"))

    val updatedDelegationsSum = delegationsSum.getOrElse(initDelegationsSum)
      .zip(delegVector).map { case (c1, c2) =>
      c1.multiply(c2).get
    }
    val updatedChoicesSum = choicesSums.getOrElse(initChoicesSum)
      .zip(choicesVectors).map { case (v1, v2) =>
      v1.zip(v2).map(c => c._1.multiply(c._2).get)
    }

    delegationsSum = Some(updatedDelegationsSum)
    choicesSums = Some(updatedChoicesSum)
    this
  }

  def getDelegationsSum: Option[Vector[ElGamalCiphertext]] = delegationsSum
  def getChoicesSum: Option[List[Vector[ElGamalCiphertext]]] = choicesSums
}