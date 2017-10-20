import common._
import java.nio.ByteBuffer

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
    val votersBallots = ballots.filter(_.isInstanceOf[VoterBallot])

    val acc = votersBallots.head.unitVector.slice(0, expertsNum).map {
      c => cs.multiply(c, votersBallots.head.asInstanceOf[VoterBallot].stake)
    }
    val delegations = votersBallots.tail.foldLeft(acc) {
      (acc, ballot) => {
        for (i <- 0 until expertsNum) {
          val Ci = cs.multiply(ballot.unitVector(i), ballot.asInstanceOf[VoterBallot].stake)
          acc(i) = cs.add(acc(i), Ci)
        }
        acc
      }
    }

    val expertsChoices = ballots.filter(_.isInstanceOf[ExpertBallot]).map {
      (ballot) => {
        val expertChoice = ballot.asInstanceOf[ExpertBallot].unitVector
        assert(expertChoice.size == 3)

        val delegatedStake = cs.decrypt(privateKey, delegations(ballot.issuerId - 1))
        expertChoice.map(c => cs.multiply(c, BigInt(delegatedStake).toByteArray))
      }
    }

    val expertsRes = expertsChoices.tail.foldLeft(expertsChoices.head) {
      (acc, choice) => {
        for (i <- 0 until 3)
          acc(i) = cs.add(acc(i), choice(i))
        acc
      }
    }

    val totalRes = votersBallots.foldLeft(expertsRes) {
      (acc, ballot) => {
        for (i <- 0 until 3) {
          val voterBallot = ballot.asInstanceOf[VoterBallot]
          val voterChoice = voterBallot.unitVector.slice(expertsNum, expertsNum + 3)
          assert(voterChoice.size == 3)

          val v = cs.multiply(voterChoice(i), voterBallot.stake)
          acc(i) = cs.add(acc(i), v)
        }
        acc
      }
    }
    assert(totalRes.size == 3)

    TallyResult(
      cs.decrypt(privateKey, totalRes(0)),
      cs.decrypt(privateKey, totalRes(1)),
      cs.decrypt(privateKey, totalRes(2))
    )
  }

  def tallyVotesV2(ballots: Seq[Ballot], privateKey: PrivKey): TallyResult = {

    var expertsNum = 0
    var unitVectorSize = 0
    var expertUnitVectorSize = 0

    // Checking the sizes of all ballots for identity
    //
    for(i <- 0 until ballots.size) {
      ballots(i) match {
        case voterBallot: VoterBallot =>
          if(expertsNum == 0){
            expertsNum = voterBallot.expertsNum
          }
          if(unitVectorSize == 0){
            unitVectorSize = voterBallot.unitVector.size
          }

          if(expertsNum != 0 && expertsNum != voterBallot.expertsNum ||
             unitVectorSize != 0 && unitVectorSize != voterBallot.unitVector.size)
            return TallyResult(0,0,0)

        case expertBallot: ExpertBallot =>
          if(expertUnitVectorSize == 0){
            expertUnitVectorSize = expertBallot.unitVector.size
          }
          if(expertUnitVectorSize != 0 && expertUnitVectorSize != expertBallot.unitVector.size)
            return TallyResult(0,0,0)
      }
    }

    // Exponentiation of the regular voters votes to the power of their stake
    //
    for(i <- 0 until ballots.size ) {
      for(j <- 0 until unitVectorSize ){

        ballots(i) match {
          case voterBallot: VoterBallot => voterBallot.unitVector(j) = cs.multiply(voterBallot.unitVector(j), voterBallot.stake)
          case _ =>
        }
      }
    }

    // Unit-wise summation of the weighted regular voters votes
    //
    var votesSum = new Array[Ciphertext](unitVectorSize)

    for(i <- 0 until votesSum.size ) {
      for(j <- 0 until ballots.size ){
        ballots(j) match {
          case voterBallot: VoterBallot =>
            if(j == 0)
              votesSum(i) = voterBallot.unitVector(i)
            else
              votesSum(i) = cs.add(voterBallot.unitVector(i), votesSum(i))
          case _ =>
        }
      }
    }

    // Decryption of the summed ballots of the regular voters
    //
    var votesResult = new Array[Message](unitVectorSize)

    for(i <- 0 until unitVectorSize ) {
      votesResult(i) = cs.decrypt(privateKey, votesSum(i))
    }

    // Exponentiation of the experts votes to the power of the delegated voters stake sum
    //
    for(i <- 0 until ballots.size ) {
      for(j <- 0 until expertUnitVectorSize ){
        ballots(i) match {
          case expertBallot: ExpertBallot => expertBallot.unitVector(j) = cs.multiply(expertBallot.unitVector(j), ByteBuffer.allocate(4).putInt(votesResult(expertBallot.issuerId - 1)).array())
          case _ =>
        }
      }
    }


    // Unit-wise summation of the weighted experts votes
    //
    var expertVotesSum = new Array[Ciphertext](expertUnitVectorSize)

    for(i <- 0 until expertVotesSum.size ) {
      for(j <- 0 until ballots.size ){
        ballots(j) match {
          case expertBallot: ExpertBallot =>
            if(j == 0)
              expertVotesSum(i) = expertBallot.unitVector(i)
            else
              expertVotesSum(i) = cs.add(expertBallot.unitVector(i), expertVotesSum(i))
          case _ =>
        }
      }
    }

    // Decryption of the summed ballots of the experts
    //
    var expertVotesResult = new Array[Message](expertUnitVectorSize)

    for(i <- 0 until expertUnitVectorSize ) {
      expertVotesResult(i) = cs.decrypt(privateKey, expertVotesSum(i))
    }

    TallyResult(
      expertVotesResult(0) + votesResult(expertsNum),
      expertVotesResult(1) + votesResult(expertsNum + 1),
      expertVotesResult(2) + votesResult(expertsNum + 2)
    )
  }
}

case class RegularVoter(val cs: Cryptosystem,
                        val voterID: Integer,
                        val expertsNum: Integer,
                        val publicKey: PubKey,
                        val stake: Array[Byte]) extends Voter {

  def produceVote(proposalID: Integer, delegationChoice: Int, choice: VoteCases.Value): Ballot = {

    val voterBallot = new VoterBallot(voterID, proposalID, expertsNum, stake)
    val randomness = for (i <- 0 until voterBallot.unitVector.size) yield cs.getRand()

    val nonZeroElementPos: Int = {
      if (delegationChoice >= 0 && delegationChoice < expertsNum) delegationChoice
      else choice match {
        case VoteCases.Yes      => expertsNum
        case VoteCases.No       => expertsNum + 1
        case VoteCases.Abstain  => expertsNum + 2
      }
    }

    for (i <- 0 until voterBallot.unitVector.size) {
      voterBallot.unitVector(i) = cs.encrypt(publicKey, randomness(i), if (i == nonZeroElementPos) 1 else 0)
    }

    voterBallot
  }
}

case class Expert(val cs: Cryptosystem,
                  val voterID: Integer,
                  val expertsNum: Integer,
                  val publicKey: PubKey) extends Voter {

  def produceVote(proposalID: Integer, delegationChoice: Int, choice: VoteCases.Value): Ballot = {

    val expertBallot = new ExpertBallot(voterID, proposalID)
    val randomness = for (i <- 0 until expertBallot.unitVector.size) yield cs.getRand()

    val nonZeroElementPos: Int =
      choice match {
        case VoteCases.Yes      => 0
        case VoteCases.No       => 1
        case VoteCases.Abstain  => 2
      }

    for (i <- 0 until expertBallot.unitVector.size) {
      expertBallot.unitVector(i) = cs.encrypt(publicKey, randomness(i), if (i == nonZeroElementPos) 1 else 0)
    }

    expertBallot
  }
}