import scala.collection.mutable.ArrayBuffer
import common._

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

    val acc = votersBallots.head.unitVector.slice(0, expertsNum)
    val delegations = votersBallots.tail.foldLeft(acc) {
      (acc, ballot) => {
        for (i <- 0 to expertsNum) {
          acc(i) = cs.add(acc(i), ballot.unitVector(i))
          acc(i) = cs.multiply(ballot.asInstanceOf[VoterBallot].stake, acc(i))
        }
        acc
      }
    }

    val expertsChoices = ballots.filter(_.isInstanceOf[ExpertBallot]).map {
      (ballot) => {
        val expertChoice = ballot.asInstanceOf[ExpertBallot].unitVector
        assert(expertChoice.size == 3)

        expertChoice.map(c => cs.add(c, delegations(ballot.issuerId)))
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

          val v = cs.multiply(voterBallot.stake, voterChoice(i))
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
}

case class RegularVoter(val cs: Cryptosystem,
                        val voterID: Integer,
                        val expertsNum: Integer,
                        val publicKey: PubKey,
                        val stake: Array[Byte]) extends Voter {

  def produceVote(proposalID: Integer, delegationChoice: Int, choice: VoteCases.Value): Ballot = {
    val unitVectorSize = expertsNum + 3
    val randomness = for (i <- 0 until unitVectorSize) yield cs.getRand()

    val nonZeroElementPos: Int = {
      if (delegationChoice > 0 && delegationChoice < expertsNum) delegationChoice
      else choice match {
        case VoteCases.Yes => expertsNum
        case VoteCases.No => expertsNum + 1
        case VoteCases.Abstain => expertsNum + 2
      }
    }

    val expertBallot = new VoterBallot(voterID, proposalID, expertsNum, stake)
    for (i <- 0 until unitVectorSize) {
      if (i != nonZeroElementPos)
        expertBallot.unitVector(i) = cs.encrypt(publicKey, randomness(i), 0)
    }
    expertBallot.unitVector(nonZeroElementPos) = cs.encrypt(publicKey, randomness(nonZeroElementPos), 1)

    expertBallot
  }
}

case class Expert(val cs: Cryptosystem,
                  val voterID: Integer,
                  val expertsNum: Integer,
                  val publicKey: PubKey) extends Voter {

  def produceVote(proposalID: Integer, delegationChoice: Int, choice: VoteCases.Value): Ballot = {
    val randomness = for (i <- 0 to 2) yield cs.getRand()

    val expertBallot = new ExpertBallot(voterID, proposalID)

    choice match {
      case VoteCases.Yes =>
        expertBallot.unitVector(0) = cs.encrypt(publicKey, randomness(0), 1)
        expertBallot.unitVector(1) = cs.encrypt(publicKey, randomness(1), 0)
        expertBallot.unitVector(2) = cs.encrypt(publicKey, randomness(2), 0)
      case VoteCases.No =>
        expertBallot.unitVector(0) = cs.encrypt(publicKey, randomness(0), 0)
        expertBallot.unitVector(1) = cs.encrypt(publicKey, randomness(1), 1)
        expertBallot.unitVector(2) = cs.encrypt(publicKey, randomness(2), 0)
      case VoteCases.Abstain =>
        expertBallot.unitVector(0) = cs.encrypt(publicKey, randomness(0), 0)
        expertBallot.unitVector(1) = cs.encrypt(publicKey, randomness(1), 0)
        expertBallot.unitVector(2) = cs.encrypt(publicKey, randomness(2), 1)
    }

    expertBallot
  }
}