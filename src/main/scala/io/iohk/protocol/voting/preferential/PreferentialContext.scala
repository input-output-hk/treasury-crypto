package io.iohk.protocol.voting.preferential

import io.iohk.protocol.CryptoContext

class PreferentialContext(val cryptoContext: CryptoContext,
                          val numberOfProposals: Int,
                          val numberOfRankedProposals: Int,
                          val numberOfExperts: Int) {

  require(numberOfExperts >= 0, "Number of experts cannot be negative")
  require(numberOfRankedProposals > 0, "There should be at least one option to rank")
  require(numberOfProposals >= numberOfRankedProposals, "There should be at least one option to vote for")
}
