package io.iohk.protocol

/**
  * ProtocolContext holds basic configuration of the voting protocol
  *
  * @param cryptoContext holds a configuration of cryptographic primitives used in the protocol
  * @param numberOfChoices holds a number of choices to vote for (e.g., if there is "Yes/No/Abstain" voting, then there are 3 choices)
  * @param numberOfExperts holds a number of experts that a voter can delegate to
  */
class ProtocolContext(val cryptoContext: CryptoContext,
                      val numberOfChoices: Int,
                      val numberOfExperts: Int) {

  require(numberOfExperts >= 0, "Number of experts cannot be negative")
  require(numberOfChoices > 0, "There should be at least one option to vote for")
}
