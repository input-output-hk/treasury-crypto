package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.{Ballot, ExpertBallot, VoterBallot}

/*
* DecryptionManager encapsulates all logic related to generation of the tally decryption shares
* Normally each committee member will create its own DecryptionManager to perform his part of the joint decryption
* This class is parametrized by committee member secret key.
* It can also be used to generate decryption shares (namely decrypted C1 components) of the faulty committee member who
* refused to publish shares by himself, so his secret key was publicly reconstructed.
*
* Note that there is an internal state used for simpli
*/
class DecryptionManager(val cs: Cryptosystem,
                        val secretKey: PrivKey,
                        ballots: Seq[Ballot]) {

  private lazy val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])
  assert(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))

  private lazy val expertsBallots = ballots.filter(_.isInstanceOf[ExpertBallot]).map(_.asInstanceOf[ExpertBallot])
  assert(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

  private var delegationsSum:   Seq[Ciphertext] = null
  private var choicesSum:  Seq[Ciphertext] = null

  def decryptC1ForDelegations(): DelegationsC1 =
  {
    delegationsSum = computeDelegationsSum()
    delegationsSum.map(decryptC1(secretKey, _))
  }

  def decryptC1ForChoices(decryptedC1ForDelegations: Seq[DelegationsC1]): ChoicesC1 =
  {
    if (delegationsSum == null)
      delegationsSum = computeDelegationsSum()

    val delegationsResult = decryptVectorOnC1(decryptedC1ForDelegations, delegationsSum)
    choicesSum = computeChoicesSum(delegationsResult)

    // Decryption shares of the summed votes
    //
    choicesSum.map(decryptC1(secretKey, _))
  }

  def decryptTally(votesC1: Seq[ChoicesC1]): Result =
  {
    if (choicesSum == null)
      throw new UninitializedFieldError("choicesSum is uninitialized")

    val votesResult = decryptVectorOnC1(votesC1, choicesSum)
    Result(
      votesResult(0),
      votesResult(1),
      votesResult(2)
    )
  }

  // Unit-wise summation of the weighted regular voters delegations
  //
  private def computeDelegationsSum(): Seq[Ciphertext] = {
    votersBallots.map(_.uvDelegations).transpose.map(
      _.zipWithIndex.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, i) = next
          cs.add(cs.multiply(delegated, votersBallots(i).stake), sum)
      }
    )
  }

  private def computeChoicesSum(delegations: Seq[Element]): Seq[Ciphertext] = {
    // Unit-wise summation of the weighted experts votes
    //
    val expertsChoicesSum = expertsBallots.map(_.uvChoice).transpose.map(
      _.zipWithIndex.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, i) = next
          cs.add(cs.multiply(delegated, delegations(expertsBallots(i).expertId)), sum)
      }
    )

    // Unit-wise summation of the weighted regular voters votes
    //
    val regularChoicesSum = votersBallots.map(_.uvChoice).transpose.map(
      _.zipWithIndex.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, i) = next
          cs.add(cs.multiply(delegated, votersBallots(i).stake), sum)
      }
    )

    expertsChoicesSum.zip(regularChoicesSum).map(x => cs.add(x._1, x._2))
  }

  private def decryptC1(privKey: PrivKey, ciphertext: Ciphertext): Point = {
    ciphertext._1.multiply(privKey)
  }

  // Unit-wise decryption of a vector, using sum of corresponding decrypted C1
  private def decryptVectorOnC1(c1Vectors: Seq[DelegationsC1], encryptedVector: Seq[Ciphertext]): Seq[BigInteger] = {

    assert(c1Vectors.forall(_.length == c1Vectors.head.length))
    assert(encryptedVector.length == c1Vectors.head.length)

    val c1Sum = c1Vectors.transpose.map(_.foldLeft(cs.infinityPoint){(sum, c1) => sum.add(c1)})

    encryptedVector.zip(c1Sum).map{case (unit, c1) => cs.discreteLog(unit._2.subtract(c1))}
  }
}
