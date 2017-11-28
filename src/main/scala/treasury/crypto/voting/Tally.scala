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

  // Removes C1 decryption shares received from violators of DKG and Tally phases
  private def filterC1( c1:                 Seq[C1],
                        dgkRecoveredKeys:   Seq[(Integer, BigInteger)],
                        skDelegationShares: Seq[KeyShares],
                        skChoisesShares:    Seq[KeyShares] = null): Seq[C1] =
  {
    val dgkViolatorsIds = dgkRecoveredKeys.map(_._1)
    val decrDelegViolatorsIds = skDelegationShares.map(_.keyShares).head.map(_.ownerID)
    val decrChoisesViolatorsIds =
      if(skChoisesShares != null)
        skChoisesShares.map(_.keyShares).head.map(_.ownerID)
      else
        Seq[Integer]()

    c1.filter(x => !dgkViolatorsIds.contains(x.issuerID))
      .filter(x => !decrDelegViolatorsIds.contains(x.issuerID))
      .filter(x => !decrChoisesViolatorsIds.contains(x.issuerID))
  }

  // Calculates the total result of voting (based on all existing ballots of voters and experts)
  // The decryption of the final result is performed by obtaining C1 components of the result (raised to the private key) from committee members
  def countVotes(cs:                  Cryptosystem,
                 ballots:             Seq[Ballot],
                 delegationsC1In:     Seq[C1],
                 choicesC1In:         Seq[C1],
                 dgkRecoveredKeys:    Seq[(Integer, BigInteger)] = Seq[(Integer, BigInteger)](),
                 skSharesDelegations: Seq[KeyShares] = Seq[KeyShares](),
                 skSharesChoises:     Seq[KeyShares] = Seq[KeyShares]()): Result = {

    val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])
    val expertsBallots = ballots.filter(_.isInstanceOf[ExpertBallot]).map(_.asInstanceOf[ExpertBallot])

    val delegationsC1 = filterC1(delegationsC1In, dgkRecoveredKeys, skSharesDelegations)
    val choicesC1 = filterC1(choicesC1In, dgkRecoveredKeys, skSharesDelegations, skSharesChoises)

    // Sum up all delegation vectors from voters. Each coordinate of the vector is multiplied to the
    // corresponding element of the other vector
    val delegationsSum = computeDelegationsSum(cs, votersBallots)

    // Get decrypted C1 for delegations using secret keys of DKG stage violators
    val dkgDelegationsC1 = dgkRecoveredKeys.map(sk => delegationsSum.map(_._1.multiply(sk._2)))

    // Reconstruct secret keys of commitee members had been absent on delegations decryption phase and get decrypted C1 using them
    val delegationsDecryptionSKs = reconstructSecretKeys(cs, skSharesDelegations)
    val delegationsDecryptionC1 = delegationsDecryptionSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))

    // Decrypt summed delegations
    val delegations = decryptVectorOnC1(cs, delegationsC1.map(_.decryptedC1) ++ dkgDelegationsC1 ++ delegationsDecryptionC1, delegationsSum)

    // Sum up all choice vectors
    // The choice vector of an expert should be raised to the power of the amount of the delegated stake
    // The choice vector of a voter should be raised to the power of the voter stake
    val choicesSum = computeChoicesSum(cs, votersBallots, expertsBallots, delegations)

    // Get decrypted C1 for choises using secret keys of DKG stage violators
    val dkgChoisesC1 = dgkRecoveredKeys.map(sk => choicesSum.map(_._1.multiply(sk._2)))

    // Reconstruct secret keys of commitee members had been absent on choises decryption phase and get decrypted C1 using them
    val choisesDecryptionSKs = reconstructSecretKeys(cs, skSharesChoises)
    val choicesDecryptionC1 = (delegationsDecryptionSKs ++ choisesDecryptionSKs).map(sk => choicesSum.map(_._1.multiply(sk)))

    // Decrypt summed choices
    val tallyRes = decryptVectorOnC1(cs, choicesC1.map(_.decryptedC1) ++ dkgChoisesC1 ++ choicesDecryptionC1, choicesSum)
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

  def reconstructSecretKeys(cs: Cryptosystem, skShares: Seq[KeyShares], threshold: Integer = 0): Array[BigInteger] =
  {
    val decryptionViolatorsShares = skShares.map(
      member =>
        member.keyShares.map(
          share =>
            (share.ownerID, OpenedShare(member.issuerID, HybridPlaintext(cs.infinityPoint, share.share.toByteArray)))
        )
    ).map(_.sortBy(_._1).map(_._2)).transpose

    decryptionViolatorsShares.map(LagrangeInterpolation.restoreSecret(cs, _, threshold)).toArray
  }
}
