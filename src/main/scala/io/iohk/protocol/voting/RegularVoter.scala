package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.voting.ballots.PublicStakeBallot

class RegularVoter(override val pctx: ProtocolContext,
                   val publicKey: PubKey,
                   val stake: BigInt) extends Voter(pctx) {

  def produceVote(proposalID: Int, choice: VotingOptions.Value, withProof: Boolean = true): PublicStakeBallot = {

    val vote = choice match {
      case VotingOptions.Yes      => pctx.numberOfExperts + 0
      case VotingOptions.No       => pctx.numberOfExperts + 1
      case VotingOptions.Abstain  => pctx.numberOfExperts + 2
    }

    PublicStakeBallot.createBallot(pctx, proposalID, vote, publicKey, stake).get
  }

  def produceDelegatedVote(proposalID: Int, delegate: Int, withProof: Boolean = true): PublicStakeBallot = {
    PublicStakeBallot.createBallot(pctx, proposalID, delegate, publicKey, stake).get
  }
}