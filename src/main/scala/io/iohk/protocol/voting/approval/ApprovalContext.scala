package io.iohk.protocol.voting.approval

import io.iohk.protocol.CryptoContext

/**
  * ApprovalContext holds basic configuration of the approval voting protocol
  *
  * @param cryptoContext holds a configuration of cryptographic primitives used in the protocol
  * @param numberOfChoices holds a number of choices to vote for (e.g., if there is "Yes/No/Abstain" voting, then there are 3 choices)
  * @param numberOfExperts holds a number of experts that a voter can delegate to
  * @param numberOfProposals holds a number of registered proposals that should be voted
  */
class ApprovalContext(val cryptoContext: CryptoContext,
                      val numberOfChoices: Int,
                      val numberOfExperts: Int,
                      val numberOfProposals: Int = 5) { // TODO: remove default

  require(numberOfExperts >= 0, "Number of experts cannot be negative")
  require(numberOfChoices > 0, "There should be at least one option to vote for")
  require(numberOfProposals > 0, "There should be at least one proposal to vote for")
}
