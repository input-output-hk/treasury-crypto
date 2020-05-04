package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.voting.ballots.ExpertBallot

case class Expert(override val pctx: ProtocolContext,
                  expertId: Int,
                  publicKey: PubKey) extends Voter(pctx) {

  def produceVote(proposalID: Int, choice: VotingOptions.Value, withProof: Boolean = true): ExpertBallot = {

    val vote = choice match {
      case VotingOptions.Yes      => 0
      case VotingOptions.No       => 1
      case VotingOptions.Abstain  => 2
    }

    ExpertBallot.createBallot(pctx, proposalID, expertId, vote, publicKey).get
  }
}
