package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.{Cryptosystem, One, VoteCases}
import treasury.crypto.voting.{Expert, RegularVoter, Voter, VoterBallot}

class VoterTest extends FunSuite {

  val cs = new Cryptosystem
  val (privKey, pubKey) = cs.createKeyPair

  test("test zero knowledge proof for Voter ballot") {
    val voterId = 6
    val numberOfExperts = 6

    val voter = new RegularVoter(cs, numberOfExperts, pubKey, One)
    val ballot = voter.produceVote(0, VoteCases.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.getUnitVector.size == numberOfExperts + Voter.VOTER_CHOISES_NUM)
  }

  test("test zero knowledge proof for Expert ballot") {
    val voterId = 6

    val voter = new Expert(cs, voterId, pubKey)
    val ballot = voter.produceVote(0, VoteCases.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.getUnitVector.size == Voter.VOTER_CHOISES_NUM)
  }
}
