package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption
import io.iohk.protocol.{CryptoContext, ProtocolContext}
import org.scalatest.FunSuite

class VoterTest extends FunSuite {

  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("test RegularVoter") {
    val numberOfExperts = 6
    val pctx = new ProtocolContext(ctx, 3, numberOfExperts)

    val voter = new RegularVoter(pctx, pubKey, 1)
    val ballot = voter.produceVote(0, VotingOptions.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.uVector.delegations.size == pctx.numberOfExperts)
    assert(ballot.uVector.choice.size == pctx.numberOfChoices)
  }

  test("test Expert") {
    val expertId = 6
    val pctx = new ProtocolContext(ctx, 3, 7)

    val voter = new Expert(pctx, expertId, pubKey)
    val ballot = voter.produceVote(0, VotingOptions.Abstain)

    assert(voter.verifyBallot(ballot))
    assert(ballot.uChoiceVector.size == pctx.numberOfChoices)
  }
}
