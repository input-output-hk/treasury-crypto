package io.iohk.protocol.voting.preferential

import io.iohk.protocol.voting.approval.ApprovalContext

import scala.util.Try

/**
  * A preferential vote is represented as an ordered list of proposal identifiers or an expert id in case of delegation.
  */
trait PreferentialVote {

  def isDirectVote: Boolean
  def isDelegatedVote: Boolean = !isDirectVote

  /** In case of a direct vote, it returns an ordered list of proposal identifiers, otherwise returns None.
    * The order defines priority of proposals. */
  def getDirectVote: Option[List[Int]]

  /** In case of a delegated vote, it returns an integer representing the expert id, otherwise returns None */
  def getDelegatedVote: Option[Int]

  def validate(implicit ctx: PreferentialContext): Boolean
}

/**
  * @param ranking an ordered list of proposal ids depending on their priorities. The head is top priority.
  */
case class DirectPreferentialVote(ranking: List[Int]) extends PreferentialVote {
  override val isDirectVote = true
  override def getDirectVote = Some(ranking)
  override def getDelegatedVote = None
  override def validate(implicit ctx: PreferentialContext): Boolean = Try {
    require(ranking.size == ctx.numberOfRankedProposals)
    require(ranking.distinct.size == ranking.size)
    ranking.foreach(p => require(p >=0 && p < ctx.numberOfProposals))
  }.isSuccess

}

case class DelegatedPreferentialVote(expertId: Int) extends PreferentialVote {
  override val isDirectVote = false
  override def getDirectVote = None
  override def getDelegatedVote = Some(expertId)
  override def validate(implicit ctx: PreferentialContext): Boolean =
    expertId >= 0 && expertId < ctx.numberOfExperts
}
