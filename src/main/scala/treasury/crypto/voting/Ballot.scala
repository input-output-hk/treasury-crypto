package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.nizk.shvzk.SHVZKProof

// The data structure for storing of the individual voter's/expert's choice
trait Ballot {
  def proposalId: Int
  def proof: SHVZKProof

  def unitVector: Array[Ciphertext]
}

case class VoterBallot(
  proposalId: Int,
  uvDelegations: Array[Ciphertext],
  uvChoice: Array[Ciphertext],
  proof: SHVZKProof,
  stake: BigInteger
) extends Ballot {

  def unitVector: Array[Ciphertext] = uvDelegations ++ uvChoice
}

case class ExpertBallot(
  proposalId: Int,
  expertId: Int,
  uvChoice: Array[Ciphertext],
  proof: SHVZKProof
) extends Ballot {

  def unitVector: Array[Ciphertext] = uvChoice
}
