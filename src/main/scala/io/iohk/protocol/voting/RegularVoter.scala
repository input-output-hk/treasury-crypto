package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.voting.ballots.VoterBallot

class RegularVoter(override val pctx: ProtocolContext,
                   val publicKey: PubKey,
                   val stake: BigInt) extends Voter(pctx) {

  def produceVote(proposalID: Int, choice: VotingOptions.Value, withProof: Boolean = true): VoterBallot = {

    val vote = choice match {
      case VotingOptions.Yes      => pctx.numberOfExperts + 0
      case VotingOptions.No       => pctx.numberOfExperts + 1
      case VotingOptions.Abstain  => pctx.numberOfExperts + 2
    }

    VoterBallot.createBallot(pctx, proposalID, vote, publicKey, stake).get
  }

  def produceDelegatedVote(proposalID: Int, delegate: Int, withProof: Boolean = true): VoterBallot = {
    VoterBallot.createBallot(pctx, proposalID, delegate, publicKey, stake).get
  }
}