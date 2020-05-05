package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.{CryptoContext, ProtocolContext}
import io.iohk.protocol.voting.ballots.{BallotSerializer, PrivateStakeBallot}
import org.scalatest.FunSuite

class PrivateStakeBallotTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.{group}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of ballot") {
    val pctx = new ProtocolContext(ctx, 3, 5)
    val stake = 13

    // test all possible votes
    for (vote <- 0 until (pctx.numberOfExperts + pctx.numberOfChoices)) {
      val ballot = PrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get

      require(ballot.uVector.delegations.size == pctx.numberOfExperts)
      require(ballot.uVector.choice.size == pctx.numberOfChoices)
      require(ballot.uVector.combine.size == pctx.numberOfExperts + pctx.numberOfChoices)
      require(ballot.vVector.delegations.size == pctx.numberOfExperts)
      require(ballot.vVector.choice.size == pctx.numberOfChoices)
      require(ballot.vVector.combine.size == pctx.numberOfExperts + pctx.numberOfChoices)

      require(ballot.verifyBallot(pctx, pubKey).isSuccess)
      require(LiftedElGamalEnc.decrypt(privKey, ballot.encryptedStake).get == stake)

      ballot.uVector.combine.zipWithIndex.foreach { case (v,i) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (i == vote) require(r == 1)
        else require(r == 0)
      }

      ballot.vVector.combine.zipWithIndex.foreach { case (v,i) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (i == vote) require(r == stake)
        else require(r == 0)
      }
    }

    // test invalid votes
    val invalidVotes = Seq(-1, pctx.numberOfExperts + pctx.numberOfChoices, 100, 2355)
    for (vote <- invalidVotes) {
      val badBallot = PrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake)
      require(badBallot.isFailure)
    }
  }

  test("serialization") {
    val pctx = new ProtocolContext(ctx, 3, 5)
    val stake = 13
    val vote = 2

    val ballot = PrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get
    val bytes = ballot.bytes
    val recoveredBallot = BallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[PrivateStakeBallot]

    require(recoveredBallot.proposalId == 0)
    require(recoveredBallot.verifyBallot(pctx, pubKey).isSuccess)

    val ballotWithoutProofs = ballot.copy(uProof = None, vProof = None)
    val recoveredBallot2 = BallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get.asInstanceOf[PrivateStakeBallot]
    require(recoveredBallot2.proposalId == 0)
    require(recoveredBallot2.uVector.delegations.size == 5 && recoveredBallot2.uVector.choice.size == 3)
    require(recoveredBallot2.vVector.delegations.size == 5 && recoveredBallot2.vVector.choice.size == 3)
    require(recoveredBallot2.uProof.isEmpty)
    require(recoveredBallot2.vProof.isEmpty)
  }
}
