package io.iohk.protocol.voting.approval.uni_delegation

import io.iohk.protocol.voting.approval.ApprovalContext

import scala.util.Try

/**
  * A uni delegation approval vote represents the choice for many proposals at once. The delegation is unified for all proposals.
  */
trait UniDelegVote {

  def isDirectVote: Boolean
  def isDelegatedVote: Boolean = !isDirectVote

  /** In case of a direct vote, it returns an ordered list of choices for each proposal, otherwise returns None. */
  def getDirectVote: Option[List[Int]]

  /** In case of a delegated vote, it returns an integer representing the expert id, otherwise returns None */
  def getDelegatedVote: Option[Int]

  def validate(implicit ctx: ApprovalContext): Boolean
}

/**
  * @param ranking an ordered list of proposal ids depending on their priorities. The head is top priority.
  */
case class DirectUniDelegVote(choices: List[Int]) extends UniDelegVote {
  override val isDirectVote = true
  override def getDirectVote = Some(choices)
  override def getDelegatedVote = None
  override def validate(implicit ctx: ApprovalContext): Boolean = Try {
    require(choices.size == ctx.numberOfProposals)
    choices.foreach(p => require(p >=0 && p < ctx.numberOfChoices))
  }.isSuccess

}

case class DelegatedUniDelegVote(expertId: Int) extends UniDelegVote {
  override val isDirectVote = false
  override def getDirectVote = None
  override def getDelegatedVote = Some(expertId)
  override def validate(implicit ctx: ApprovalContext): Boolean =
    expertId >= 0 && expertId < ctx.numberOfExperts
}
