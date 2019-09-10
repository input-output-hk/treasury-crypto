package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.core.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.util.Try

object Tally {

  case class Result(yes: BigInt, no: BigInt, abstain: BigInt)

  /**
    * Unit-wise summation of the weighted regular voters delegations
    *
    * @param cs A Cryptosystem instance
    * @param votersBallots
    * @return Sequence of ciphertexts, each of which represents the summation of a particular bit of the unit vector for
    *         all voters
    */
  def computeDelegationsSum(cs: Cryptosystem, votersBallots: Seq[VoterBallot]): Seq[Ciphertext] = {
    votersBallots.map(_.uvDelegations).transpose.map(
      _.zip(votersBallots).foldLeft(ElGamalCiphertext(cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, ballot) = next
          cs.add(cs.multiply(delegated, ballot.stake), sum)
      }
    )
  }

  /**
    * Unit-wise summation of the weighted voters and experts choices
    *
    * @param cs A cryptosystem instance
    * @param votersBallots
    * @param expertsBallots
    * @param delegations An array representing delegations for all experts. The size of the array should be exactly
    *                    the number of experts. Indexes of the array elements match indexes of the experts.
    * @return Sequence of ciphertexts, each of which represents the summation of a particular bit of the unit vector for
    *         all voters and experts
    */
  def computeChoicesSum(cs: Cryptosystem,
                        votersBallots: Seq[VoterBallot],
                        expertsBallots: Seq[ExpertBallot],
                        delegations: Seq[Element]): Seq[Ciphertext] = {
    // Unit-wise summation of the weighted experts votes
    //
    val expertsChoicesSum = expertsBallots.map(_.uvChoice).transpose.map(
      _.zip(expertsBallots).foldLeft(ElGamalCiphertext(cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, ballot) = next
          cs.add(cs.multiply(delegated, delegations(ballot.expertId)), sum)
      }
    )

    // Unit-wise summation of the weighted regular voters votes
    //
    val regularChoicesSum = votersBallots.map(_.uvChoice).transpose.map(
      _.zip(votersBallots).foldLeft(ElGamalCiphertext(cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, ballot) = next
          cs.add(cs.multiply(delegated, ballot.stake), sum)
      }
    )

    if (expertsChoicesSum.nonEmpty && regularChoicesSum.nonEmpty)
      expertsChoicesSum.zip(regularChoicesSum).map(x => cs.add(x._1, x._2))
    else if (expertsChoicesSum.nonEmpty)
      expertsChoicesSum
    else
      regularChoicesSum
  }

  /**
    * Compute final tally based on the decryption shares
    *
    * @param cs Cryptosystem instance
    * @param ballots all the ballots collected during the voting stage
    * @param choicesC1 decryptions shares of choices bits of the unit vector. It is crucial that this array contains
    *                  decryption shares of all committe members, including those who failed to submit shares by themselves
    *                  thus publicly recostructed
    * @param delegations vector of decrypted delegations for each expert
    * @return final result of the voting for the particular project
    */
  def countVotes(cs: Cryptosystem,
                 ballots: Seq[Ballot],
                 choicesC1: Seq[Seq[Point]],
                 delegations: Seq[Element])
                (implicit dlogGroup: DiscreteLogGroup): Try[Result] = Try {

    val votersBallots = ballots.collect { case b: VoterBallot => b }
    if (votersBallots.size > 0) {
      require(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))
      require(votersBallots.head.uvDelegations.length == delegations.length)
    }

    val expertsBallots = ballots.collect { case b: ExpertBallot => b }
    require(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

    val choicesSum = Tally.computeChoicesSum(cs, votersBallots, expertsBallots, delegations)
    val votesResult = Tally.decryptVectorOnC1(cs, choicesC1, choicesSum)

    Result(
      votesResult(0),
      votesResult(1),
      votesResult(2)
    )
  }

  /**
    * Unit-wise decryption of a vector of integers, using decrypted C1 component.
    * Note that since decryption requires solving discrete log with brute force, the encrypted values should be limited.
    * Morever, wrong decryption shares could lead to infinite computation since discreteLog will continuously try
    * to brute force encrypted value.
    *
    * @param cs A Cryptosystem instance
    * @param c1Vectors Decryption shares for each element of the encryptedVector
    * @param encryptedVector A vector of encrypted integers.
    * @return
    */
  def decryptVectorOnC1(cs: Cryptosystem, c1Vectors: Seq[Seq[Point]], encryptedVector: Seq[Ciphertext])
                       (implicit dlogGroup: DiscreteLogGroup): Seq[BigInt] = {

    require(c1Vectors.forall(_.length == c1Vectors.head.length))
    require(encryptedVector.length == c1Vectors.head.length)

    val c1Sum = c1Vectors.transpose.map(_.foldLeft(cs.infinityPoint){(sum, c1) => sum.multiply(c1).get})

    encryptedVector.zip(c1Sum).map{case (unit, c1) => LiftedElGamalEnc.discreteLog(unit.c2.divide(c1).get).get}
  }
}
