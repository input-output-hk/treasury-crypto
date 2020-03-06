package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKVerifier}
import io.iohk.protocol.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

abstract class Voter(val ctx: CryptoContext) {

  protected implicit val group = ctx.group
  protected implicit val hash = ctx.hash

  def publicKey: PubKey

  def verifyBallot(ballot: Ballot): Boolean = {
    new SHVZKVerifier(publicKey, ballot.unitVector, ballot.proof).verifyProof()
  }

  protected def produceUnitVector(size: Int, nonZeroPos: Int): (Array[ElGamalCiphertext], Array[Randomness]) = {
    val ciphertexts = new Array[ElGamalCiphertext](size)
    val randomness = new Array[Randomness](size)

    for (i <- 0 until size) {
      randomness(i) = group.createRandomNumber
      ciphertexts(i) = LiftedElGamalEnc.encrypt(publicKey, randomness(i), if (i == nonZeroPos) 1 else 0).get
    }

    (ciphertexts, randomness)
  }
}

object Voter {
  val VOTER_CHOISES_NUM = 3
}

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

    val (uvDelegVector, uvDelegRand) = produceUnitVector(expertsNum, -1)
    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, nonZeroPos)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvDelegVector ++ uvChoiceVector,
          expertsNum + nonZeroPos, uvDelegRand ++ uvChoiceRand).produceNIZK().get
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }

  def produceDelegatedVote(proposalID: Int, delegate: Int, withProof: Boolean = true): VoterBallot = {
    assert(delegate >= 0 && delegate < expertsNum)

    val (uvDelegVector, uvDelegRand) = produceUnitVector(expertsNum, delegate)
    val (uvChoiceVector, uvChoiceRand) = produceUnitVector(Voter.VOTER_CHOISES_NUM, -1)
    val proof =
      if (withProof)
        new SHVZKGen(publicKey, uvDelegVector ++ uvChoiceVector, delegate, uvDelegRand ++ uvChoiceRand).produceNIZK().get
      else null

    VoterBallot(proposalID, uvDelegVector, uvChoiceVector, proof, stake)
  }
}

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
