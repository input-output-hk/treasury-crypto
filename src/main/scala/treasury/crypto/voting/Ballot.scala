package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._

// The data structure for storing of the individual voter's/expert's choice
trait Ballot {
  val proposalId: Int

  def getUnitVector(): Array[Ciphertext]
}

case class VoterBallot(override val proposalId: Int,
                       val uvDelegations: Array[Ciphertext],
                       val uvChoice: Array[Ciphertext],
                       val stake: BigInteger) extends Ballot {

  override def getUnitVector() = uvDelegations ++ uvChoice
}

case class ExpertBallot(override val proposalId: Int,
                        val expertId: Int,
                        val uvChoice: Array[Ciphertext]) extends Ballot {
  override def getUnitVector() = uvChoice
}