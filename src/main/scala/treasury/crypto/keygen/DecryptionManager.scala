package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.nizk.ElgamalDecrNIZK
import treasury.crypto.voting.Tally
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.collection.mutable.ArrayBuffer

/*
* DecryptionManager encapsulates all logic related to generation of the tally decryption shares
* Normally each committee member will create its own DecryptionManager to perform his part of the joint decryption
* This class is parametrized by committee member secret key.
* It can also be used to generate decryption shares (namely decrypted C1 components) of the faulty committee member who
* refused to publish shares by himself, so his secret key was publicly reconstructed.
*
* Note that there is an internal state used for simpli
*/
class DecryptionManager(cs:               Cryptosystem,
                        ownId:            Integer,
                        keyPair:          KeyPair,
                        dkgViolatorsSKs:  Seq[BigInteger],
                        ballots:          Seq[Ballot],
                        recoveryThreshold: Integer = 0) {

  private lazy val (secretKey, publicKey) = keyPair

  private lazy val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])
  assert(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))

  private lazy val expertsBallots = ballots.filter(_.isInstanceOf[ExpertBallot]).map(_.asInstanceOf[ExpertBallot])
  assert(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

  private var delegationsSum:   Seq[Ciphertext] = null
  private var choicesSum:  Seq[Ciphertext] = null

  private var decryptionViolatorsSKs = new ArrayBuffer[BigInteger]()

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

  def validateChoicesC1(c1: C1Share): Boolean = {
    validateC1(c1, choicesSum)
  }

  def decryptC1ForDelegations(): C1Share = {
    delegationsSum = Tally.computeDelegationsSum(cs, votersBallots)

    val decryptionShares = delegationsSum.map(_._1.multiply(secretKey).normalize)
    val decSharesProofs = delegationsSum.map(ElgamalDecrNIZK.produceNIZK(cs, _, secretKey))

    C1Share(ownId, publicKey, decryptionShares, decSharesProofs)
  }

  def decryptC1ForChoices(decryptedC1ForDelegationsIn: Seq[C1Share], skShares: Seq[KeyShares] = Seq[KeyShares]()): C1Share = {
    if (delegationsSum == null)
      delegationsSum = Tally.computeDelegationsSum(cs, votersBallots)

    decryptionViolatorsSKs ++= Tally.reconstructSecretKeys(cs, skShares, recoveryThreshold)

    val decryptionViolatorsC1 = decryptionViolatorsSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))
    val dkgViolatorsC1 = dkgViolatorsSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))

    val decryptedC1ForDelegations = decryptedC1ForDelegationsIn.map(_.decryptedC1)
    val delegationsResult = Tally.decryptVectorOnC1(cs, decryptedC1ForDelegations ++ dkgViolatorsC1 ++ decryptionViolatorsC1, delegationsSum)
    choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegationsResult)

    // Decryption shares of the summed votes
    //
    val decryptionShares = choicesSum.map(_._1.multiply(secretKey).normalize)
    val decSharesProofs = choicesSum.map(ElgamalDecrNIZK.produceNIZK(cs, _, secretKey))

    C1Share(ownId, publicKey, decryptionShares, decSharesProofs)
  }

  def decryptTally(votesC1: Seq[C1Share], skShares: Seq[KeyShares] = Seq[KeyShares]()): Result = {
    if (choicesSum == null)
      throw UninitializedFieldError("choicesSum is uninitialized")

    decryptionViolatorsSKs ++= Tally.reconstructSecretKeys(cs, skShares, recoveryThreshold)

    val decryptionViolatorsC1 = decryptionViolatorsSKs.map(sk => choicesSum.map(_._1.multiply(sk)))
    val dkgViolatorsC1 = dkgViolatorsSKs.map(sk => choicesSum.map(_._1.multiply(sk)))

    val votesResult = Tally.decryptVectorOnC1(cs, votesC1.map(_.decryptedC1) ++ dkgViolatorsC1 ++ decryptionViolatorsC1, choicesSum)
    Result(
      votesResult(0),
      votesResult(1),
      votesResult(2)
    )
  }
}
