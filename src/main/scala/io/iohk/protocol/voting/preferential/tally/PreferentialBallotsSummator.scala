package io.iohk.protocol.voting.preferential.tally

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.protocol.voting.preferential.{PreferentialContext, PreferentialVoterBallot}

import scala.util.Try

class PreferentialBallotsSummator(ctx: PreferentialContext) {
  import ctx.cryptoContext.group

  val neutralCiphertext = ElGamalCiphertext(group.groupIdentity, group.groupIdentity)

  private var delegationsSum: Option[Vector[ElGamalCiphertext]] = None
  private var rankingsSum: Option[List[Vector[ElGamalCiphertext]]] = None

  private def initRankingsSum: List[Vector[ElGamalCiphertext]] =
    (0 until ctx.numberOfProposals).map { _ =>
      Vector.fill[ElGamalCiphertext](ctx.numberOfRankedProposals)(neutralCiphertext)
    }.toList
  private def initDelegationsSum = Vector.fill[ElGamalCiphertext](ctx.numberOfExperts)(neutralCiphertext)

  def getDelegationsSum: Option[Vector[ElGamalCiphertext]] = delegationsSum
  def getRankingsSum: Option[List[Vector[ElGamalCiphertext]]] = rankingsSum

  def addVoterBallot(ballot: PreferentialVoterBallot): Try[PreferentialBallotsSummator] = Try {
    require(ballot.delegVector.length == ctx.numberOfExperts, "Invalid preferential voter ballot: invalid number of delegation bits in the unit vector")
    require(ballot.rankVectors.length == ctx.numberOfProposals, "Invalid preferential voter ballot: invalid number of rank vectors")
    ballot.rankVectors.foreach(v =>
      require(v.rank.length == ctx.numberOfRankedProposals, "Invalid voter ballot: invalid number of choice bits in the unit vector"))

    val updatedDelegationsSum = delegationsSum.getOrElse(initDelegationsSum)
      .zip(ballot.weightedDelegationVector).map { case (c1, c2) =>
      c1.multiply(c2).get
    }
    val updatedRankingsSum = rankingsSum.getOrElse(initRankingsSum)
      .zip(ballot.weightedRankVectors).map { case (v1, v2) =>
      v1.zip(v2).map(c => c._1.multiply(c._2).get)
    }

    delegationsSum = Some(updatedDelegationsSum)
    rankingsSum = Some(updatedRankingsSum)
    this
  }
}
