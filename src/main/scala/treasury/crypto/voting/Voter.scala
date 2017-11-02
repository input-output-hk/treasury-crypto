package treasury.crypto.voting

import java.math.BigInteger

import treasury.crypto._
import treasury.crypto.core._

sealed trait Voter {
  val cs: Cryptosystem
  val voterID: Integer
  val expertsNum: Integer
  val publicKey: PubKey

  // Produces encrypted ballot with NIZKs for its contents.
  def produceVote(proposalID: Integer, delegationChoice: Int, choice: VoteCases.Value): Ballot

  // Calculates the total result of voting (based on all existing ballots of voters and experts)
  // NOTE: The privateKey parameter is temporary for simplified testing. In full version the decrypted by each committee member C1 part of ElGamal ciphertext should be obtained and multiplicated to each other for decryption of the each element of the unit vector.
  def tallyVotes(ballots: Seq[Ballot], privateKey: PrivKey): TallyResult = {
    val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])

    // Create an accumulator where we will collect the sum of all of the voter's delegations
    // Put the head ballot as initial state of the acc and don't forget to raise an encrypted delegation to the stake amount
    val acc = votersBallots.head.uvDelegations.map {
      c => cs.multiply(c, votersBallots.head.stake)
    }
    assert(acc.size == expertsNum)

    // Sum up all other delegation vectors from voters. Each coordinate of the vector is multiplied to the
    // corresponding element of the other vector
    val delegations = votersBallots.tail.foldLeft(acc) {
      (acc, ballot) => {
        for (i <- 0 until expertsNum) {
          val Ci = cs.multiply(ballot.uvDelegations(i), ballot.stake)
          acc(i) = cs.add(acc(i), Ci)
        }
        acc
      }
    }

    // The choice vector of an expert should be raised to the power of the amount of the delegated stake
    val expertsChoices = ballots.filter(_.isInstanceOf[ExpertBallot]).map {
      (ballot) => {
        val expertChoice = ballot.asInstanceOf[ExpertBallot].uvChoice
        assert(expertChoice.size == Ballot.VOTER_CHOISES_NUM)

        val delegatedStake = cs.decrypt(privateKey, delegations(ballot.issuerId))
        expertChoice.map(c => cs.multiply(c, delegatedStake))
      }
    }

    // Sum up all choice vectors from experts
    val expertsRes = expertsChoices.tail.foldLeft(expertsChoices.head) {
      (acc, choice) => {
        for (i <- 0 until Ballot.VOTER_CHOISES_NUM)
          acc(i) = cs.add(acc(i), choice(i))
        acc
      }
    }
    assert(expertsRes.size == Ballot.VOTER_CHOISES_NUM)

    // Sum up all choice vectors from voters (taking into account their stake)
    val totalRes = votersBallots.foldLeft(expertsRes) {
      (acc, ballot) => {
        for (i <- 0 until Ballot.VOTER_CHOISES_NUM) {
          val v = cs.multiply(ballot.uvChoice(i), ballot.stake)
          acc(i) = cs.add(acc(i), v)
        }
        acc
      }
    }
    assert(totalRes.size == Ballot.VOTER_CHOISES_NUM)

    TallyResult(
      cs.decrypt(privateKey, totalRes(0)),
      cs.decrypt(privateKey, totalRes(1)),
      cs.decrypt(privateKey, totalRes(2))
    )
  }

  def tallyVotesV2(ballots: Seq[Ballot], privateKey: PrivKey): TallyResult = {

    var expertsNum = 0
    var regularUvDelegationsSize = 0
    var regularUvChoiceSize = 0
    var expertUnitVectorSize = 0

    // Checking the sizes of all ballots for identity
    //
    for(i <- 0 until ballots.size)
    {
      ballots(i) match
      {
        case voterBallot: VoterBallot =>

          if(expertsNum == 0)
            expertsNum = voterBallot.expertsNum

          if(regularUvDelegationsSize == 0)
            regularUvDelegationsSize = voterBallot.uvDelegations.size

          if(regularUvChoiceSize == 0)
            regularUvChoiceSize = voterBallot.uvChoice.size

          if(expertsNum != 0 && expertsNum != voterBallot.expertsNum ||
            regularUvDelegationsSize != 0 && regularUvDelegationsSize != voterBallot.uvDelegations.size ||
            regularUvChoiceSize != 0 && regularUvChoiceSize != voterBallot.uvChoice.size)
            return TallyResult(Zero,Zero,Zero)

        case expertBallot: ExpertBallot =>

          if(expertUnitVectorSize == 0)
            expertUnitVectorSize = expertBallot.uvChoice.size

          if(expertUnitVectorSize != 0 && expertUnitVectorSize != expertBallot.uvChoice.size)
            return TallyResult(Zero,Zero,Zero)
      }
    }

    var regularVotersBallots  = ballots.filter(_.isInstanceOf[VoterBallot]).map(_.asInstanceOf[VoterBallot])
    var expertsBallots        = ballots.filter(_.isInstanceOf[ExpertBallot]).map(_.asInstanceOf[ExpertBallot])

    // Exponentiation of the regular voters ddelegations and votes to the power of their stake
    //
    for(i <- 0 until regularVotersBallots.size)
    {
      for(j <- 0 until regularUvDelegationsSize )
        regularVotersBallots(i).uvDelegations(j) = cs.multiply(regularVotersBallots(i).uvDelegations(j), regularVotersBallots(i).stake)

      for(j <- 0 until regularUvChoiceSize )
        regularVotersBallots(i).uvChoice(j) = cs.multiply(regularVotersBallots(i).uvChoice(j), regularVotersBallots(i).stake)
    }

    // Unit-wise summation of the weighted regular voters delegations
    //
    var delegationsSum  = new Array[Ciphertext](regularUvDelegationsSize)

    for(i <- 0 until delegationsSum.size)
    {
      for(j <- 0 until regularVotersBallots.size)
      {
            if(delegationsSum(i) == null)
              delegationsSum(i) = regularVotersBallots(j).uvDelegations(i)
            else
              delegationsSum(i) = cs.add(regularVotersBallots(j).uvDelegations(i), delegationsSum(i))
      }
    }

    // Unit-wise summation of the weighted regular voters votes
    //
    var regularVotesSum = new Array[Ciphertext](regularUvChoiceSize)

    for(i <- 0 until regularVotesSum.size)
    {
      for(j <- 0 until regularVotersBallots.size)
      {
        if(regularVotesSum(i) == null)
          regularVotesSum(i) = regularVotersBallots(j).uvChoice(i)
        else
          regularVotesSum(i) = cs.add(regularVotersBallots(j).uvChoice(i), regularVotesSum(i))
      }
    }

    // Decryption of the summed delegations of the regular voters
    //
    var delegationsResult = new Array[BigInteger](regularUvDelegationsSize)

    for(i <- 0 until regularUvDelegationsSize)
      delegationsResult(i) = cs.decrypt(privateKey, delegationsSum(i))

    // Decryption of the summed votes of the regular voters
    //
    var regularVotesResult = new Array[BigInteger](regularUvChoiceSize)

    for(i <- 0 until regularUvChoiceSize)
      regularVotesResult(i) = cs.decrypt(privateKey, regularVotesSum(i))

    // Exponentiation of the experts votes to the power of the delegated voters stake sum
    //
    for(i <- 0 until expertsBallots.size)
      for(j <- 0 until expertUnitVectorSize )
        expertsBallots(i).uvChoice(j) = cs.multiply(expertsBallots(i).uvChoice(j), delegationsResult(expertsBallots(i).issuerId))

    // Unit-wise summation of the weighted experts votes
    //
    var expertVotesSum = new Array[Ciphertext](expertUnitVectorSize)

    for(i <- 0 until expertVotesSum.size)
    {
      for(j <- 0 until expertsBallots.size)
      {
        if(expertVotesSum(i) == null)
          expertVotesSum(i) = expertsBallots(j).uvChoice(i)
        else
          expertVotesSum(i) = cs.add(expertsBallots(j).uvChoice(i), expertVotesSum(i))
      }
    }

    // Decryption of the summed ballots of the experts
    //
    var expertVotesResult = new Array[BigInteger](expertUnitVectorSize)

    for(i <- 0 until expertUnitVectorSize ) {
      expertVotesResult(i) = cs.decrypt(privateKey, expertVotesSum(i))
    }

    // Total sum of regular voters and experts votes
    //
    TallyResult(
      expertVotesResult(0).add(regularVotesResult(0)),
      expertVotesResult(1).add(regularVotesResult(1)),
      expertVotesResult(2).add(regularVotesResult(2))
    )
  }
}

case class RegularVoter(val cs: Cryptosystem,
                        val voterID: Integer,
                        val expertsNum: Integer,
                        val publicKey: PubKey,
                        val stake: BigInteger) extends Voter {

  def produceVote(proposalID: Integer, delegationChoice: Int, choice: VoteCases.Value): Ballot = {

    val ballot = new VoterBallot(voterID, proposalID, expertsNum, stake)
    var choiceIdx = 0

    val randDeleg = for (i <- 0 until ballot.uvDelegations.size) yield cs.getRand
    val randChoice = for (i <- 0 until ballot.uvChoice.size) yield cs.getRand

    if (delegationChoice >= 0 && delegationChoice < expertsNum) {
      for (i <- 0 until ballot.uvDelegations.size) {
        ballot.uvDelegations(i) = cs.encrypt(publicKey, randDeleg(i), if (i == delegationChoice) One else Zero)
      }
      for (i <- 0 until ballot.uvChoice.size) {
        ballot.uvChoice(i) = cs.encrypt(publicKey, randChoice(i), Zero)
      }
      choiceIdx = delegationChoice
    }
    else {
      for (i <- 0 until ballot.uvDelegations.size) {
        ballot.uvDelegations(i) = cs.encrypt(publicKey, randDeleg(i), Zero)
      }
      for (i <- 0 until ballot.uvChoice.size) {
        val pos = choice match {
          case VoteCases.Yes      => 0
          case VoteCases.No       => 1
          case VoteCases.Abstain  => 2
        }
        ballot.uvChoice(i) = cs.encrypt(publicKey, randChoice(i), if (i == pos) One else Zero)
        choiceIdx = expertsNum + pos
      }
    }

//    val nizk =
//      new UnitVectorLogNIZK(cs, publicKey,
//      ballot.uvDelegations ++ ballot.uvChoice,
//      choiceIdx,
//      randDeleg ++ randChoice)
//      .produceNIZK()

    ballot
  }
}

case class Expert(val cs: Cryptosystem,
                  val voterID: Integer,
                  val expertsNum: Integer,
                  val publicKey: PubKey) extends Voter {

  def produceVote(proposalID: Integer, delegationChoice: Int, choice: VoteCases.Value): Ballot = {

    val expertBallot = new ExpertBallot(voterID, proposalID)
    val randomness = for (i <- 0 until expertBallot.uvChoice.size) yield cs.getRand

    val nonZeroElementPos: Int =
      choice match {
        case VoteCases.Yes      => 0
        case VoteCases.No       => 1
        case VoteCases.Abstain  => 2
      }

    for (i <- 0 until expertBallot.uvChoice.size) {
      expertBallot.uvChoice(i) = cs.encrypt(publicKey, randomness(i), if (i == nonZeroElementPos) One else Zero)
    }

    expertBallot
  }
}