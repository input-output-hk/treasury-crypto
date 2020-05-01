package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.shvzk.SHVZKGen
import io.iohk.protocol.voting.ballots.ExpertBallot

case class Expert(override val ctx: CryptoContext,
                  expertId: Int,
                  publicKey: PubKey) extends Voter(ctx) {

  def produceVote(proposalID: Int, choice: VotingOptions.Value, withProof: Boolean = true): ExpertBallot = {

    val nonZeroPos = choice match {
      case VotingOptions.Yes      => 0
      case VotingOptions.No       => 1
      case VotingOptions.Abstain  => 2
    }

    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvChoiceVector, nonZeroPos, uvChoiceRand).produceNIZK().get
      else null

    ExpertBallot(proposalID, expertId, uvChoiceVector, proof)
  }
}
