package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.nizk.shvzk.SHVZKProof

// The data structure for storing of the individual voter's/expert's choice
trait Ballot {
  val proposalId: Int
  val proof: SHVZKProof

  def getUnitVector: Array[Ciphertext]
}

case class VoterBallot(override val proposalId: Int,
                       val uvDelegations: Array[Ciphertext],
                       val uvChoice: Array[Ciphertext],
                       override val proof: SHVZKProof,
                       val stake: BigInteger) extends Ballot {

  override def getUnitVector() = uvDelegations ++ uvChoice
}

case class ExpertBallot(override val proposalId: Int,
                        val expertId: Int,
                        val uvChoice: Array[Ciphertext],
                        override val proof: SHVZKProof) extends Ballot {
  override def getUnitVector() = uvChoice
}