package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.{Cryptosystem,One,VoteCases}
import treasury.crypto.voting.{RegularVoter, VoterBallot}

class VoterTest extends FunSuite {

  val cs = new Cryptosystem
  val (privKey, pubKey) = cs.createKeyPair

  test("test zero knowledge proof for Voter ballot") {
    val voterId = 6
    val numberOfExperts = 6

    val voter = new RegularVoter(cs, numberOfExperts, pubKey, One)
    val ballot = voter.produceVote(0, VoteCases.Abstain).asInstanceOf[VoterBallot]

    assert(ballot.uvDelegations.size == numberOfExperts)
  }
}
