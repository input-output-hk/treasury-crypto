package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class VoterTest extends FunSuite {

  val cs = new CryptoContext(None)
  import cs.{group, hash}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("test zero knowledge proof for Voter ballot") {
    val voterId = 6
    val numberOfExperts = 6

    val voter = new RegularVoter(cs, numberOfExperts, pubKey, 1)
    val ballot = voter.produceVote(0, VotingOptions.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.unitVector.size == numberOfExperts + Voter.VOTER_CHOISES_NUM)
  }

  test("test zero knowledge proof for Expert ballot") {
    val voterId = 6

    val voter = new Expert(cs, voterId, pubKey)
    val ballot = voter.produceVote(0, VotingOptions.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.unitVector.size == Voter.VOTER_CHOISES_NUM)
  }
}
