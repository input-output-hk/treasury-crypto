package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.ballots.{BallotSerializer, ExpertBallot, VoterBallot}
import org.scalatest.FunSuite

class BallotTest extends FunSuite {

  val cs = new CryptoContext(None)
  import cs.{group, hash}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("voter ballot serialization") {
    val numberOfExperts = 6
    val voter = new RegularVoter(cs, numberOfExperts, pubKey, 1)
    val ballotBytes = voter.produceVote(0, VotingOptions.Abstain).bytes
    val ballot = BallotSerializer.parseBytes(ballotBytes, Option(cs.group)).get.asInstanceOf[VoterBallot]

    assert(voter.verifyBallot(ballot))
    assert(ballot.proposalId == 0)
    assert(ballot.uvDelegations.length == numberOfExperts)
    assert(ballot.uvChoice.length == Voter.VOTER_CHOISES_NUM)
    assert(ballot.stake == 1)
  }

  test("voter ballot serialization 2") {
    val numberOfExperts = 0
    val voter = new RegularVoter(cs, numberOfExperts, pubKey, 1)
    val ballotBytes = voter.produceVote(0, VotingOptions.Abstain).bytes
    val ballot = BallotSerializer.parseBytes(ballotBytes, Option(cs.group)).get.asInstanceOf[VoterBallot]

    assert(voter.verifyBallot(ballot))
    assert(ballot.proposalId == 0)
    assert(ballot.uvDelegations.length == numberOfExperts)
    assert(ballot.uvChoice.length == Voter.VOTER_CHOISES_NUM)
    assert(ballot.stake == 1)
  }

  test("expert ballot serialization 2") {
    val id = 5
    val voter = new Expert(cs, id, pubKey)
    val ballotBytes = voter.produceVote(0, VotingOptions.Abstain).bytes
    val ballot = BallotSerializer.parseBytes(ballotBytes, Option(cs.group)).get.asInstanceOf[ExpertBallot]

    assert(voter.verifyBallot(ballot))
    assert(ballot.proposalId == 0)
    assert(ballot.unitVector.length == Voter.VOTER_CHOISES_NUM)
    assert(ballot.expertId == id)
  }
}
