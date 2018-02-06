package treasury.crypto.keygen

import treasury.crypto.core.{Ciphertext, Cryptosystem}
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.nizk.ElgamalDecrNIZK
import treasury.crypto.voting.Tally
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

class DecryptionValidator(cs: Cryptosystem, ballots: Seq[Ballot]) {

  private lazy val votersBallots = ballots.collect { case b: VoterBallot => b }
  assert(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))

  private lazy val expertsBallots = ballots.collect { case b: ExpertBallot => b }
  assert(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

  private val delegationsSum: Seq[Ciphertext] = Tally.computeDelegationsSum(cs, votersBallots)

  private def validateC1(c1: C1Share, vectorForValidation: Seq[Ciphertext]): Boolean =
  {
    (vectorForValidation, c1.decryptedC1, c1.decryptedC1Proofs).zipped.toList.forall {
      unit =>
        val ciphertext = unit._1
        val C1sk = unit._2
        val plaintext = ciphertext._2.subtract(C1sk)
        val proof = unit._3

        ElgamalDecrNIZK.verifyNIZK(cs, c1.issuerPubKey, ciphertext, plaintext, proof)
    }
  }

  def validateDelegationsC1(c1: C1Share): Boolean = {
    validateC1(c1, delegationsSum)
  }

  def validateChoicesC1(c1: C1Share, delegationsC1: Seq[C1Share]): Boolean = {
    val delegationsResult = Tally.decryptVectorOnC1(cs, delegationsC1.map(_.decryptedC1), delegationsSum)
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegationsResult)
    validateC1(c1, choicesSum)
  }
}
