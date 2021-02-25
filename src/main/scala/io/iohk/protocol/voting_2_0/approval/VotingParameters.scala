package io.iohk.protocol.voting_2_0.approval

import io.iohk.protocol.CryptoContext

object VoteOption extends Enumeration {
  type VoteOption = Value
  val Yes, No, Abstain = Value

  def toInt(vote: VoteOption): Int = {
    vote match {
      case Yes => 0
      case No => 1
      case Abstain => 2
    }
  }
  val optionsNum: Int = 3
}

case class VotingParameters(cryptoContext: CryptoContext,
                            numberOfProposals: Int,
                            numberOfExperts: Int,
                            numberOfOptions: Int = VoteOption.optionsNum)
