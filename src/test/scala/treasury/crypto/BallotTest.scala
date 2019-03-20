package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.{Cryptosystem, One, VoteCases}
import treasury.crypto.voting._
import treasury.crypto.voting.ballots.{BallotCompanion, ExpertBallot, VoterBallot}

class BallotTest extends FunSuite {

  val cs = new Cryptosystem
  val (privKey, pubKey) = cs.createKeyPair

  test("voter ballot serialization") {
    val numberOfExperts = 6
    val voter = new RegularVoter(cs, numberOfExperts, pubKey, One)
    val ballotBytes = voter.produceVote(0, VoteCases.Abstain).bytes
    val ballot = BallotCompanion.parseBytes(ballotBytes, Option(cs)).get.asInstanceOf[VoterBallot]

    assert(voter.verifyBallot(ballot))
    assert(ballot.proposalId == 0)
    assert(ballot.uvDelegations.length == numberOfExperts)
    assert(ballot.uvChoice.length == Voter.VOTER_CHOISES_NUM)
    assert(ballot.stake.equals(One))
  }

  test("voter ballot serialization 2") {
    val numberOfExperts = 0
    val voter = new RegularVoter(cs, numberOfExperts, pubKey, One)
    val ballotBytes = voter.produceVote(0, VoteCases.Abstain).bytes
    val ballot = BallotCompanion.parseBytes(ballotBytes, Option(cs)).get.asInstanceOf[VoterBallot]

    assert(voter.verifyBallot(ballot))
    assert(ballot.proposalId == 0)
    assert(ballot.uvDelegations.length == numberOfExperts)
    assert(ballot.uvChoice.length == Voter.VOTER_CHOISES_NUM)
    assert(ballot.stake.equals(One))
  }

  test("expert ballot serialization 2") {
    val id = 5
    val voter = new Expert(cs, id, pubKey)
    val ballotBytes = voter.produceVote(0, VoteCases.Abstain).bytes
    val ballot = BallotCompanion.parseBytes(ballotBytes, Option(cs)).get.asInstanceOf[ExpertBallot]

    assert(voter.verifyBallot(ballot))
    assert(ballot.proposalId == 0)
    assert(ballot.unitVector.length == Voter.VOTER_CHOISES_NUM)
    assert(ballot.expertId == id)
  }
}
