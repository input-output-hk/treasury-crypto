package treasury.crypto.decryption

import treasury.crypto.core._
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.primitives.hash.CryptographicHash
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.nizk.ElgamalDecrNIZK
import treasury.crypto.voting.Tally
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.util.Try

/*
* DecryptionManager encapsulates logic related to generation/recover of the tally decryption shares
* It can also be used to generate decryption shares (namely decrypted C1 components) of the faulty committee member who
* refused to publish shares by himself, so his secret key was publicly reconstructed.
*/
class DecryptionManager(cs:               Cryptosystem,
                        ballots:          Seq[Ballot],
                        recoveryThreshold: Integer = 0)
                       (implicit dlogGroup: DiscreteLogGroup, hash: CryptographicHash) {

  lazy val votersBallots = ballots.collect { case b: VoterBallot => b }
  assert(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))

  lazy val expertsBallots = ballots.collect { case b: ExpertBallot => b }
  assert(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

  lazy val delegationsSum: Seq[Ciphertext] = Tally.computeDelegationsSum(cs, votersBallots)

  /**
    * Validates decrypted share generated by some committee member. Each decryption share (C1Share) should contain
    * an array of the decrypted c1 components for the corresponding ciphertexts.
    *
    * @param issuerPubKey A public key of a committee member who created the C1Share
    * @param c1Share C1Share datastructure containing an array of decrypted c1 components for the array of ciphertexts
    *                together with NIZK proofs that these decrypted components are valid
    * @param vectorForValidation An array of ciphertexts that should be decrypted with c1 components from C1Share
    * @return Success(_) if succeeds
    */
  private def validateC1Share(issuerPubKey: PubKey, c1Share: C1Share, vectorForValidation: Seq[Ciphertext]): Try[Unit] = Try {
    require(c1Share.decryptedC1.length == vectorForValidation.length, "Wrong C1Share lenght")

    for (i <- vectorForValidation.indices) {
      val ciphertext = vectorForValidation(i)
      val C1sk = c1Share.decryptedC1(i)._1
      val plaintext = ciphertext.c2.divide(C1sk).get
      val proof = c1Share.decryptedC1(i)._2

      require(ElgamalDecrNIZK.verifyNIZK(issuerPubKey, ciphertext, plaintext, proof), "Invalid proof")
    }
  }

  /**
    * Wrapper over validateC1Share(issuerPubKey: PubKey, c1Share: C1Share, vectorForValidation: Seq[Ciphertext])
    * Validates C1Share issued specifically for the first stage of the tally phase when committee members jointly
    * decrypts delegations part of the summed unit vector
    *
    * @param issuerPubKey A public key of a committee member who created the C1Share
    * @param c1Share C1Share containint an array of decrypted c1 components for the summed ciphertexts that
    *                represent delegation bits of the unit vector.
    * @return Success(_) if succeeds
    */
  def validateDelegationsC1(issuerPubKey: PubKey, c1Share: C1Share): Try[Unit] = {
    validateC1Share(issuerPubKey, c1Share, delegationsSum)
  }

  /**
    * Whapper over validateC1Share(issuerPubKey: PubKey, c1Share: C1Share, vectorForValidation: Seq[Ciphertext])
    * Validates C1Share issued specifically for the second stage of the tally phase when committee members jointly
    * decrypts results (choices part of the summed unit vector)
    *
    * @param issuerPubKey A public key of a committee member who created the C1Share
    * @param choicesC1 C1Share containint an array of decrypted c1 components for the summed ciphertexts that
    *                  represent choices bits of the unit vector.
    * @param delegations An array that represents number of delegations for each expert
    * @return Success(_) if succeeds
    */
  def validateChoicesC1(issuerPubKey: PubKey,
                        choicesC1: C1Share,
                        delegations: Seq[Element]): Try[Unit] = {
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)
    validateC1Share(issuerPubKey, choicesC1, choicesSum)
  }

  /**
    * Generate C1Share for the delegations part of the summed unit vector. This function should be used by
    * a committee member on the first stage of the Tally.
    * Note that for each proposal there would be a different set of ballots, thus C1Share would be created for each
    * proposal separately
    *
    * @param issuerId Committee member identifier
    * @param proposalId Proposal identifier
    * @param secretKey Secret key of the committee member
    * @return C1Share
    */
  def decryptC1ForDelegations(issuerId: Integer, proposalId: Int, secretKey: PrivKey): C1Share = {
    val shares = delegationsSum.map { unit =>
      val decryptedC1 = unit.c1.pow(secretKey).get
      val proof = ElgamalDecrNIZK.produceNIZK(unit, secretKey).get
      (decryptedC1, proof)
    }

    C1Share(proposalId, issuerId, shares)
  }

  /**
    * Generate C1Share for the choices part of the summed unit vector. This function should be used by
    * a committee member on the second stage of the Tally.
    * Note that for each proposal there would be a different set of ballots, thus C1Share would be created for each
    * proposal separately
    *
    * @param issuerId Committee member identifier
    * @param proposalId Proposal identifier
    * @param secretKey Secret key of the committee member
    * @param delegations An array that represents number of delegations for each expert
    * @return C1Share
    */
  def decryptC1ForChoices(issuerId: Integer, proposalId: Int, secretKey: PrivKey, delegations: Seq[Element]): C1Share = {
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)

    val shares = choicesSum.map { unit =>
      val decryptedC1 = unit.c1.pow(secretKey).get
      val proof = ElgamalDecrNIZK.produceNIZK(unit, secretKey).get
      (decryptedC1, proof)
    }

    C1Share(proposalId, issuerId, shares)
  }

  /**
    * Decrypt a vector of c1 components by multiplying them on the secret key
    *
    * @param privKeys a list of priv keys, the `vector` will be decrypted for each key separately
    * @param vector vector of Points to decrypt
    * @return a list of decrypted vectors (for each secret key),
    *         each vector itself is a seq of Points, thus there will be Seq[ Seq[Point] ]
    */
  def decryptVector(privKeys: Seq[PrivKey], vector: Seq[Point]): Seq[Seq[Point]] = {
    privKeys.map(key => vector.map(_.pow(key).get))
  }

  /**
    * Recover decrypted C1 of the faulty committee members (who didn't submit C1Share by themselves).
    * Provided with private keys of the faulty CMs (jointly recovered by other CMs) we are able
    * to compute decrypted C1 for delegations
    *
    * @param privKeys list of private keys of the faulty CMs
    * @return a list of decrypted C1s for delegations, for each private key
    */
  def recoverDelegationsC1(privKeys: Seq[PrivKey]): Seq[Seq[Point]] = {
    decryptVector(privKeys, delegationsSum.map(_.c1))
  }

  /**
    * Recover decrypted C1 of the faulty committee members (who didn't submit C1Share by themselves).
    * Provided with private keys of the faulty CMs (jointly recovered by other CMs) we are able
    * to compute decrypted C1 for delegations
    *
    * @param privKeys list of private keys of the faulty CMs
    * @param delegations previously computed delegations
    * @return a list of decrypted C1s for choices, for each private key
    */
  def recoverChoicesC1(privKeys: Seq[PrivKey], delegations: Seq[Element]): Seq[Seq[Point]] = {
    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)
    decryptVector(privKeys, choicesSum.map(_.c1))
  }

  def computeDelegations(delegationsC1: Seq[Seq[Point]]): Seq[Element] = {
    Tally.decryptVectorOnC1(cs, delegationsC1, delegationsSum)
  }

  def computeChoicesSum(delegations: Seq[Element]): Seq[Ciphertext] = {
    Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)
  }

  def computeTally(choicesC1: Seq[Seq[Point]], delegations: Seq[Element]): Try[Tally.Result] = {
    Tally.countVotes(cs, votersBallots ++ expertsBallots, choicesC1, delegations)
  }
}
