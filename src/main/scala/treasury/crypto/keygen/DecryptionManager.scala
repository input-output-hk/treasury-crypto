package treasury.crypto.keygen

import java.math.BigInteger

import org.bouncycastle.math.ec.ECPoint
import treasury.crypto.core._
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.nizk.ElgamalDecrNIZK
import treasury.crypto.voting.Tally
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

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
//                        ownId:            Integer,
//                        keyPair:          KeyPair,
//                        dkgViolatorsSKs:  Seq[BigInteger],
                        ballots:          Seq[Ballot],
                        recoveryThreshold: Integer = 0) {

//  private lazy val (secretKey, publicKey) = keyPair

  private lazy val votersBallots = ballots.collect { case b: VoterBallot => b }
  assert(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))

  private lazy val expertsBallots = ballots.collect { case b: ExpertBallot => b }
  assert(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

  val delegationsSum: Seq[Ciphertext] = Tally.computeDelegationsSum(cs, votersBallots)

  private def validateC1Share(issuerPubKey: PubKey, c1Share: C1Share, vectorForValidation: Seq[Ciphertext]): Try[Unit] = Try {
    require(c1Share.decryptedC1.length == vectorForValidation.length, "Wrong C1Share lenght")

    for (i <- vectorForValidation.indices) {
      val ciphertext = vectorForValidation(i)
      val C1sk = c1Share.decryptedC1(i)._1
      val plaintext = ciphertext._2.subtract(C1sk)
      val proof = c1Share.decryptedC1(i)._2

      require(ElgamalDecrNIZK.verifyNIZK(cs, issuerPubKey, ciphertext, plaintext, proof), "Invalid proof")
    }
  }

  def validateDelegationsC1(issuerPubKey: PubKey, c1Share: C1Share): Try[Unit] = {
    validateC1Share(issuerPubKey, c1Share, delegationsSum)
  }

  def validateChoicesC1(issuerPubKey: PubKey,
                        choicesC1: C1Share,
                        delegations: Seq[Element]): Try[Unit] = {
    //val delegationsResult = Tally.decryptVectorOnC1(cs, delegationsC1, delegationsSum)
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)
    validateC1Share(issuerPubKey, choicesC1, choicesSum)
  }

  def decryptC1ForDelegations(issuerId: Integer, proposalId: Int, secretKey: PrivKey): C1Share = {
    val shares = delegationsSum.map { unit =>
      val decryptedC1 = unit._1.multiply(secretKey).normalize
      val proof = ElgamalDecrNIZK.produceNIZK(cs, unit, secretKey)
      (decryptedC1, proof)
    }

    C1Share(proposalId, issuerId, shares)
  }

  /**
    * Decrypt vector of c1 points by multiplying them on the secret key
    *
    * @param privKeys a list of priv keys, the `vector` will be decrypted for each key separetaly
    * @param vector vector of Points to decrypt
    * @return a list of decrypted vectors, each vector itself is a seq of Points, thus there will be Seq[ Seq[Point] ]
    */
  def decryptVector(privKeys: Seq[PrivKey], vector: Seq[Point]): Seq[Seq[Point]] = {
    privKeys.map(key => vector.map(_.multiply(key)))
  }

  /**
    * Recover decrypted C1 of the faulty committee members (who didn't submit C1Share by themselves).
    * Provided KeyShares from operating committee members we reconstcruct secret keys of the faulty members
    * and then compute decrypted C1 for delegations
    * @param skShares list of KeyShares, each of them is produced by a working committee member and represents his shares
    *                 for all faulty members
    * @return a list of decrypted C1s for delegations, for each provided
    */
  def recoverDelegationsC1(skShares: Seq[KeyShares]): Seq[Seq[Point]] = {
    val decryptionViolatorsSKs = Tally.reconstructSecretKeys(cs, skShares, recoveryThreshold)
    decryptVector(decryptionViolatorsSKs, delegationsSum.map(_._1))
  }

  def recoverChoicesC1(skShares: Seq[KeyShares], choicesSum: Seq[Ciphertext]): Seq[Seq[Point]] = {
    val decryptionViolatorsSKs = Tally.reconstructSecretKeys(cs, skShares, recoveryThreshold)
    decryptVector(decryptionViolatorsSKs, choicesSum.map(_._1))
  }

  def computeChoicesSum(delegations: Seq[Element]): Seq[Ciphertext] = {
    Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)
  }

  def computeDelegations(delegationsC1: Seq[Seq[Point]]): Seq[Element] = {
    Tally.decryptVectorOnC1(cs, delegationsC1, delegationsSum)
  }

  def decryptC1ForChoices(issuerId: Integer, proposalId: Int, secretKey: PrivKey, delegations: Seq[Element]): C1Share = {
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)

    val shares = choicesSum.map { unit =>
      val decryptedC1 = unit._1.multiply(secretKey).normalize
      val proof = ElgamalDecrNIZK.produceNIZK(cs, unit, secretKey)
      (decryptedC1, proof)
    }

    C1Share(proposalId, issuerId, shares)
  }

  /**
    * Compute final tally based on the decryption shares
    *
    * @param choicesC1 decryptions shares of choices bits of the unit vector
    * @param delegations vector of decrypted delegations for each expert
    * @return final result of the voting for the particular project
    */
  def decryptTally(choicesC1: Seq[Seq[Point]], delegations: Seq[Element]): Result = {
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)
    val votesResult = Tally.decryptVectorOnC1(cs, choicesC1, choicesSum)

    Result(
      votesResult(0),
      votesResult(1),
      votesResult(2)
    )
  }
}
