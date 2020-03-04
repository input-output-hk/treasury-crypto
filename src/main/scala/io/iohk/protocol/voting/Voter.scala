package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.protocol.Cryptosystem
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKVerifier}
import io.iohk.protocol.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

abstract class Voter(implicit dlogGroup: DiscreteLogGroup, hash: CryptographicHash) {
  def cs: Cryptosystem
  def publicKey: PubKey

  def verifyBallot(ballot: Ballot): Boolean = {
    new SHVZKVerifier(publicKey, ballot.unitVector, ballot.proof).verifyProof()
  }

  protected def produceUnitVector(size: Int, nonZeroPos: Int): (Array[ElGamalCiphertext], Array[Randomness]) = {
    val ciphertexts = new Array[ElGamalCiphertext](size)
    val randomness = new Array[Randomness](size)

    for (i <- 0 until size) {
      randomness(i) = cs.getRand
      ciphertexts(i) = LiftedElGamalEnc.encrypt(publicKey, randomness(i), if (i == nonZeroPos) 1 else 0).get
    }

    (ciphertexts, randomness)
  }
}

object Voter {
  val VOTER_CHOISES_NUM = 3
}

class RegularVoter(val cs: Cryptosystem,
                   val expertsNum: Integer,
                   val publicKey: PubKey,
                   val stake: BigInt)
                  (implicit dlogGroup: DiscreteLogGroup, hash: CryptographicHash) extends Voter {

  def produceVote(proposalID: Integer, choice: VotingOptions.Value, withProof: Boolean = true): VoterBallot = {

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

  def produceDelegatedVote(proposalID: Integer, delegate: Int, withProof: Boolean = true): VoterBallot = {
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

case class Expert(cs: Cryptosystem,
                  expertId: Int,
                  publicKey: PubKey)
                 (implicit dlogGroup: DiscreteLogGroup, hash: CryptographicHash) extends Voter {

  def produceVote(proposalID: Integer, choice: VotingOptions.Value, withProof: Boolean = true): ExpertBallot = {

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
