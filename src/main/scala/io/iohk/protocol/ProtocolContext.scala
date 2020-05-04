package io.iohk.protocol

class ProtocolContext(val cryptoContext: CryptoContext,
                      val numberOfChoices: Int,
                      val numberOfExperts: Int) {

  require(numberOfExperts >= 0)
  require(numberOfChoices > 0)    // we should have at least one option to vote for
}
