package io.iohk.protocol

package object voting {

  object VotingOptions extends Enumeration {
    val Yes, No, Abstain = Value
  }
}
