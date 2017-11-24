package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.keygen._

object Tally {

  case class Result(yes: BigInteger, no: BigInteger, abstain: BigInteger) extends HasSize
  {
    def size: Int =
    {
      yes.toByteArray.size + no.toByteArray.size + abstain.toByteArray.size
    }
  }

  // Calculates the total result of voting (based on all existing ballots of voters and experts)
  // The decryption of the final result is performed by obtaining C1 components of the result (raised to the private key) from committee members
  def countVotes(cs:                  Cryptosystem,
                 ballots:             Seq[Ballot],
                 delegationsC1:       Seq[C1],
                 choicesC1:           Seq[C1],
                 skSharesDelegations: Seq[KeyShares] = Seq[KeyShares](),
                 skSharesChoises:     Seq[KeyShares] = Seq[KeyShares]()): Result = {

    val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])
    val expertsBallots = ballots.filter(_.isInstanceOf[ExpertBallot]).map(_.asInstanceOf[ExpertBallot])

    // Sum up all delegation vectors from voters. Each coordinate of the vector is multiplied to the
    // corresponding element of the other vector
    val delegationsSum = computeDelegationsSum(cs, votersBallots)

    // Reconstruct secret keys of commitee members had been absent on delegations decryption phase and get decrypted C1 using them
    val delegationsDecryptionSKs = reconstructSecretKeys(cs, skSharesDelegations)
    val delegationsDecryptionC1 = delegationsDecryptionSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))

    // Decrypt summed delegations
    val delegations = decryptVectorOnC1(cs, delegationsC1.map(_.decryptedC1) ++ delegationsDecryptionC1, delegationsSum)

    // Sum up all choice vectors
    // The choice vector of an expert should be raised to the power of the amount of the delegated stake
    // The choice vector of a voter should be raised to the power of the voter stake
    val choicesSum = computeChoicesSum(cs, votersBallots, expertsBallots, delegations)

    // Reconstruct secret keys of commitee members had been absent on choises decryption phase and get decrypted C1 using them
    val choisesDecryptionSKs = reconstructSecretKeys(cs, skSharesChoises)
    val choicesDecryptionC1 = (delegationsDecryptionSKs ++ choisesDecryptionSKs).map(sk => choicesSum.map(_._1.multiply(sk)))

    // Decrypt summed choices
    val tallyRes = decryptVectorOnC1(cs, choicesC1.map(_.decryptedC1) ++ choicesDecryptionC1, choicesSum)
    assert(tallyRes.size == Voter.VOTER_CHOISES_NUM)

    Result(tallyRes(0), tallyRes(1), tallyRes(2))
  }

  // Unit-wise summation of the weighted regular voters delegations
  //
  def computeDelegationsSum(cs: Cryptosystem, votersBallots: Seq[VoterBallot]): Seq[Ciphertext] = {
    votersBallots.map(_.uvDelegations).transpose.map(
      _.zip(votersBallots).foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, ballot) = next
          cs.add(cs.multiply(delegated, ballot.stake), sum)
      }
    )
  }

  def computeChoicesSum(cs: Cryptosystem,
                        votersBallots: Seq[VoterBallot],
                        expertsBallots: Seq[ExpertBallot],
                        delegations: Seq[Element]): Seq[Ciphertext] = {
    // Unit-wise summation of the weighted experts votes
    //
    val expertsChoicesSum = expertsBallots.map(_.uvChoice).transpose.map(
      _.zip(expertsBallots).foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, ballot) = next
          cs.add(cs.multiply(delegated, delegations(ballot.expertId)), sum)
      }
    )

    // Unit-wise summation of the weighted regular voters votes
    //
    val regularChoicesSum = votersBallots.map(_.uvChoice).transpose.map(
      _.zip(votersBallots).foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, ballot) = next
          cs.add(cs.multiply(delegated, ballot.stake), sum)
      }
    )

    expertsChoicesSum.zip(regularChoicesSum).map(x => cs.add(x._1, x._2))
  }

  // Unit-wise decryption of a vector, using sum of corresponding decrypted C1
  //
  def decryptVectorOnC1(cs: Cryptosystem, c1Vectors: Seq[Seq[Point]], encryptedVector: Seq[Ciphertext]): Seq[BigInteger] = {

    assert(c1Vectors.forall(_.length == c1Vectors.head.length))
    assert(encryptedVector.length == c1Vectors.head.length)

    val c1Sum = c1Vectors.transpose.map(_.foldLeft(cs.infinityPoint){(sum, c1) => sum.add(c1)})

    encryptedVector.zip(c1Sum).map{case (unit, c1) => cs.discreteLog(unit._2.subtract(c1))}
  }

  def reconstructSecretKeys(cs: Cryptosystem, skShares: Seq[KeyShares]): Array[BigInteger] =
  {
    val decryptionViolatorsShares = skShares.map(
      member =>
        member.keyShares.map(
          share =>
            (share.ownerID, OpenedShare(member.issuerID, HybridPlaintext(cs.infinityPoint, share.share.toByteArray)))
        )
    ).map(_.sortBy(_._1).map(_._2)).transpose

    decryptionViolatorsShares.map(LagrangeInterpolation.restoreSecret(cs, _)).toArray
  }
}
