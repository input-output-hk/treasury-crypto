package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class VoterTest extends FunSuite {

  val ctx = new CryptoContext(None)
  import ctx.{group, hash}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("test zero knowledge proof for Voter ballot") {
    val voterId = 6
    val numberOfExperts = 6

    val voter = new RegularVoter(ctx, numberOfExperts, pubKey, 1)
    val ballot = voter.produceVote(0, VotingOptions.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.unitVector.size == numberOfExperts + Voter.VOTER_CHOISES_NUM)
  }

  test("test zero knowledge proof for Expert ballot") {
    val voterId = 6

    val voter = new Expert(ctx, voterId, pubKey)
    val ballot = voter.produceVote(0, VotingOptions.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.unitVector.size == Voter.VOTER_CHOISES_NUM)
  }

  test("test zero knowledge proof for PrivateVoter ballot") {
    val numberOfExperts = 6
    val stake = 13

    val voter = new PrivateVoter(ctx, numberOfExperts, pubKey, stake)
    val ballot = voter.createBallot(0, Right(2)).get

    require(ballot.verifyProofs(pubKey).isSuccess)
    require(LiftedElGamalEnc.decrypt(privKey, ballot.encryptedStake).get == stake)
    ballot.uVector.combine.zipWithIndex.foreach { case (v,i) =>
      val r = LiftedElGamalEnc.decrypt(privKey, v).get
      if (i == 2) require(r == 1)
      else require(r == 0)
    }


  }
}
