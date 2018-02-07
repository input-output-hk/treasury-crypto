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

  def validateChoicesC1(choicesC1: C1Share, delegationsC1: Seq[C1Share]): Boolean = {
    val delegationsResult = Tally.decryptVectorOnC1(cs, delegationsC1.map(_.decryptedC1), delegationsSum)
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegationsResult)
    validateC1(choicesC1, choicesSum)
  }

  def decryptC1ForDelegations(): C1Share = {
    val decryptionShares = delegationsSum.map(_._1.multiply(secretKey).normalize)
    val decSharesProofs = delegationsSum.map(ElgamalDecrNIZK.produceNIZK(cs, _, secretKey))

    C1Share(ownId, publicKey, decryptionShares, decSharesProofs)
  }

  private def computeChoicesSum(decryptedC1ForDelegationsIn: Seq[C1Share],
                                skShares: Seq[KeyShares] = Seq()): Seq[Ciphertext] = {
    val decryptionViolatorsSKs = Tally.reconstructSecretKeys(cs, skShares, recoveryThreshold)

    val decryptionViolatorsC1 = decryptionViolatorsSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))
    val dkgViolatorsC1 = dkgViolatorsSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))

    val decryptedC1ForDelegations = decryptedC1ForDelegationsIn.map(_.decryptedC1)
    val delegationsResult = Tally.decryptVectorOnC1(cs, decryptedC1ForDelegations ++ dkgViolatorsC1 ++ decryptionViolatorsC1, delegationsSum)

    Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegationsResult)
  }

  def decryptC1ForChoices(decryptedC1ForDelegationsIn: Seq[C1Share],
                          skShares: Seq[KeyShares] = Seq()): C1Share = {
    val choicesSum = computeChoicesSum(decryptedC1ForDelegationsIn, skShares)

    // Decryption shares of the summed votes
    //
    val decryptionShares = choicesSum.map(_._1.multiply(secretKey).normalize)
    val decSharesProofs = choicesSum.map(ElgamalDecrNIZK.produceNIZK(cs, _, secretKey))

    C1Share(ownId, publicKey, decryptionShares, decSharesProofs)
  }

  /**
    * Compute final tally based on the decryption shares
    *
    * @param delegationsC1 decryption shares of the delegations bits of the unit vector
    * @param choicesC1 decryptions shares of choices bits of the unit vector
    * @param delegSkShares shares of the secret key of the committe members who failed to provide decryption shares
    *                      for the DELEGATIONS bits. Having these secret key shares everyone is able to reconstruct
    *                      a violator secret key and then compute missing decryption shares
    * @param choicesSkShares shares of the secret key of the committe members who failed to provide decryption shares
    *                        for the CHOICES bits. Having these secret key shares everyone is able to reconstruct
    *                        a violator secret key and then compute missing decryption shares
    * @return final result of the voting for the particular project
    */
  def decryptTally(delegationsC1: Seq[C1Share],
                   choicesC1: Seq[C1Share],
                   delegSkShares: Seq[KeyShares] = Seq(),
                   choicesSkShares: Seq[KeyShares] = Seq()): Result = {
    val choicesSum = computeChoicesSum(delegationsC1, delegSkShares)

    val decryptionViolatorsSKs = Tally.reconstructSecretKeys(cs, choicesSkShares, recoveryThreshold)

    val decryptionViolatorsChoicesC1 = decryptionViolatorsSKs.map(sk => choicesSum.map(_._1.multiply(sk)))
    val dkgViolatorsChoicesC1 = dkgViolatorsSKs.map(sk => choicesSum.map(_._1.multiply(sk)))

    val allChoicesC1 = choicesC1.map(_.decryptedC1) ++ dkgViolatorsChoicesC1 ++ decryptionViolatorsChoicesC1

    val votesResult = Tally.decryptVectorOnC1(cs, allChoicesC1, choicesSum)
    Result(
      votesResult(0),
      votesResult(1),
      votesResult(2)
    )
  }
}
