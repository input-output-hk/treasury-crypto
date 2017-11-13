package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core.{Ciphertext, _}
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.{Ballot, ExpertBallot, VoterBallot}

class CommitteeMember(
                       val cs: Cryptosystem,
                       val h: Point,
                       val transportKeyPair: KeyPair,
                       val committeeMembersPubKeys: Seq[PubKey],
                       var delegationsSum:   Array[Ciphertext] = null,
                       var expertsVotesSum:  Array[Ciphertext] = null,
                       var regularVotesSum:  Array[Ciphertext] = null) {

  private val dkg = new DistrKeyGen(cs, h, transportKeyPair, committeeMembersPubKeys)
  val secretKey = cs.getRand
  val ownId: Integer = dkg.ownID

  def setKeyR1(): R1Data = {
    dkg.doRound1(secretKey.toByteArray)
  }

  def setKeyR2(r1Data: Seq[R1Data]): R2Data = {
    dkg.doRound2(r1Data)
  }

  def setKeyR3(r2Data: Seq[R2Data]): R3Data = {
    dkg.doRound3(r2Data)
  }

  def setKeyR4(r3Data: Seq[R3Data]): R4Data = {
    dkg.doRound4(r3Data)
  }

  def setKeyR5_1(r4Data: Seq[R4Data]): R5_1Data = {
    dkg.doRound5_1(r4Data)
  }

  def setKeyR5_2(r5_1Data: Seq[R5_1Data]): R5_2Data = {
    dkg.doRound5_2(r5_1Data)
  }

  def decryptC1ForDelegations(ballots: Seq[Ballot]): DelegationsC1 =
  {
    val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])

    assert(votersBallots.forall(_.uvDelegations.length == votersBallots.head.uvDelegations.length))

    // Unit-wise summation of the weighted regular voters delegations
    //
    delegationsSum = votersBallots.map(_.uvDelegations).transpose.map(
      _.zipWithIndex.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, i) = next
          cs.add(cs.multiply(delegated, votersBallots(i).stake), sum)
      }
    ).toArray

    val decryptedC1 = delegationsSum.map(cs.decryptC1(secretKey, _))

    DelegationsC1(decryptedC1)
  }

  def decryptC1ForVotes(ballots: Seq[Ballot], decryptedC1ForDelegations: Seq[DelegationsC1]): VotesC1 =
  {
    val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])
    val expertsBallots = ballots.filter(_.isInstanceOf[ExpertBallot]).map(_.asInstanceOf[ExpertBallot])

    assert(expertsBallots.forall(_.uvChoice.length == expertsBallots.head.uvChoice.length))

    assert(votersBallots.forall(_.uvChoice.length == votersBallots.head.uvChoice.length))

    val c1 = decryptedC1ForDelegations.map(_.decryptedC1)
    val delegationsResult = cs.decryptVectorOnC1(c1, delegationsSum)

    // Unit-wise summation of the weighted experts votes
    //
    expertsVotesSum = expertsBallots.map(_.uvChoice).transpose.map(
      _.zipWithIndex.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, i) = next
          cs.add(cs.multiply(delegated, delegationsResult(expertsBallots(i).expertId)), sum)
      }
    ).toArray

    // Unit-wise summation of the weighted regular voters votes
    //
    regularVotesSum = votersBallots.map(_.uvChoice).transpose.map(
      _.zipWithIndex.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
        (sum, next) =>
          val (delegated, i) = next
          cs.add(cs.multiply(delegated, votersBallots(i).stake), sum)
      }
    ).toArray

    // Decryption of the summed votes of the experts
    //
    val decryptedC1Experts = expertsVotesSum.map(cs.decryptC1(secretKey, _))

    // Decryption of the summed votes of the regular voters
    //
    val decryptedC1Regular = regularVotesSum.map(cs.decryptC1(secretKey, _))

    VotesC1(decryptedC1Regular, decryptedC1Experts)
  }

  def decryptTally(votesC1: Seq[VotesC1]): Result =
  {
    val c1Experts = votesC1.map(_.decryptedC1Experts)
    val expertsVotesResult = cs.decryptVectorOnC1(c1Experts, expertsVotesSum)

    val c1RegularVoters = votesC1.map(_.decryptedC1Regular)
    val regularVotesResult = cs.decryptVectorOnC1(c1RegularVoters, regularVotesSum)

    Result(
      expertsVotesResult(0).add(regularVotesResult(0)),
      expertsVotesResult(1).add(regularVotesResult(1)),
      expertsVotesResult(2).add(regularVotesResult(2))
    )
  }
}
