package io.iohk.protocol.voting_2_0.preferential

import io.iohk.protocol.CryptoContext

case class VotingParameters(cryptoContext: CryptoContext,
                            shortlistSize: Int,
                            projectsNum: Int,
                            expertsNum: Int)
