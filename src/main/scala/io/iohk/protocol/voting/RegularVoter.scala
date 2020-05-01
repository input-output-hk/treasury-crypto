package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.shvzk.SHVZKGen
import io.iohk.protocol.voting.ballots.VoterBallot

class RegularVoter(override val ctx: CryptoContext,
                   val expertsNum: Int,
                   val publicKey: PubKey,
                   val stake: BigInt) extends Voter(ctx) {

  def produceVote(proposalID: Int, choice: VotingOptions.Value, withProof: Boolean = true): VoterBallot = {

    val nonZeroPos = choice match {
      case VotingOptions.Yes      => 0
      case VotingOptions.No       => 1
      case VotingOptions.Abstain  => 2
    }

    val (uvDelegVector, uvDelegRand) = buildUnitVector(expertsNum, -1)
    val (uvChoiceVector, uvChoiceRand) = buildUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvDelegVector ++ uvChoiceVector,
          expertsNum + nonZeroPos, uvDelegRand ++ uvChoiceRand).produceNIZK().get
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }

  def produceDelegatedVote(proposalID: Int, delegate: Int, withProof: Boolean = true): VoterBallot = {
    assert(delegate >= 0 && delegate < expertsNum)

    val (uvDelegVector, uvDelegRand) = buildUnitVector(expertsNum, delegate)
    val (uvChoiceVector, uvChoiceRand) = buildUnitVector(Voter.VOTER_CHOISES_NUM, -1)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvDelegVector ++ uvChoiceVector, delegate, uvDelegRand ++ uvChoiceRand).produceNIZK().get
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }
}