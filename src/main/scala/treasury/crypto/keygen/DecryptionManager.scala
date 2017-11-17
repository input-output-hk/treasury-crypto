package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.{Ballot, ExpertBallot, Tally, VoterBallot}

/*
* DecryptionManager encapsulates all logic related to generation of the tally decryption shares
* Normally each committee member will create its own DecryptionManager to perform his part of the joint decryption
* This class is parametrized by committee member secret key.
* It can also be used to generate decryption shares (namely decrypted C1 components) of the faulty committee member who
* refused to publish shares by himself, so his secret key was publicly reconstructed.
*
* Note that there is an internal state used for simpli
*/
class DecryptionManager(cs:                   Cryptosystem,
                        ownId:                Integer,
                        secretKey:            PrivKey,
                        violatorsSecretKeys:  Seq[BigInteger],
                        ballots:              Seq[Ballot]) {

  private lazy val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])
  assert(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))

  private lazy val expertsBallots = ballots.filter(_.isInstanceOf[ExpertBallot]).map(_.asInstanceOf[ExpertBallot])
  assert(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

  private var delegationsSum:   Seq[Ciphertext] = null
  private var choicesSum:  Seq[Ciphertext] = null

  def decryptC1ForDelegations(): DelegationsC1 =
  {
    delegationsSum = Tally.computeDelegationsSum(cs, votersBallots)
    DelegationsC1(ownId, delegationsSum.map(_._1.multiply(secretKey).normalize))
  }

  def decryptC1ForChoices(decryptedC1ForDelegationsIn: Seq[DelegationsC1]): ChoicesC1 =
  {
    if (delegationsSum == null)
      delegationsSum = Tally.computeDelegationsSum(cs, votersBallots)

    val violatorsC1 = violatorsSecretKeys.map(sk => delegationsSum.map(_._1.multiply(sk)))

    val decryptedC1ForDelegations = decryptedC1ForDelegationsIn.map(_.decryptedC1)
    val delegationsResult = Tally.decryptVectorOnC1(cs, decryptedC1ForDelegations ++ violatorsC1, delegationsSum)
    choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegationsResult)

    // Decryption shares of the summed votes
    //
    ChoicesC1(ownId, choicesSum.map(c => c._1.multiply(secretKey).normalize))
  }

  def decryptTally(votesC1: Seq[ChoicesC1]): Result =
  {
    if (choicesSum == null)
      throw UninitializedFieldError("choicesSum is uninitialized")

    val violatorsC1 = violatorsSecretKeys.map(sk => choicesSum.map(_._1.multiply(sk)))

    val votesResult = Tally.decryptVectorOnC1(cs, votesC1.map(_.decryptedC1) ++ violatorsC1, choicesSum)
    Result(
      votesResult(0),
      votesResult(1),
      votesResult(2)
    )
  }
}
