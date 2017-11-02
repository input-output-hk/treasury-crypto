package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._

// The data structure for storing of the individual voter's/expert's choice
trait Ballot {

  val issuerId: Int
  val proposalId: Int

  def getUnitVector(): Array[Ciphertext]
}

object Ballot {
  val VOTER_CHOISES_NUM = 3
}

case class VoterBallot(override val issuerId: Int,
                       override val proposalId: Int,
                       val expertsNum: Int,
                       val stake: BigInteger) extends Ballot {
  // Unit vector of expertsNum + voterChoisesNum elements
  val uvDelegations: Array[Ciphertext] = new Array(expertsNum)
  val uvChoice: Array[Ciphertext] = new Array(Ballot.VOTER_CHOISES_NUM)

  override def getUnitVector(): Array[Ciphertext] = uvDelegations ++ uvChoice

//  var unitNizks: Array[UnitNIZK] = null
//  var unitsSumNizk: UnitsSumNIZK = new UnitsSumNIZK
}

case class ExpertBallot(override val issuerId: Int,
                        override val proposalId: Int) extends Ballot {
  val uvChoice: Array[Ciphertext] = new Array(Ballot.VOTER_CHOISES_NUM)

  override def getUnitVector(): Array[Ciphertext] = uvChoice
}