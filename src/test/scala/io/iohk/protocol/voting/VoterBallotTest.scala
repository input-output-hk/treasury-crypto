package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.{CryptoContext, ProtocolContext}
import org.scalatest.FunSuite

class VoterBallotTest extends FunSuite {

  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("VoterBallot interface") {
    val pctx = new ProtocolContext(ctx, 3, 5)
    val stake = 13
    val vote = DelegatedVote(2)

    val ballots = Seq(
      PublicStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get,
      PrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get)

    for (ballot <- ballots) {
      require(ballot.weightedUnitVector.delegations.size == pctx.numberOfExperts)
      require(ballot.weightedUnitVector.choice.size == pctx.numberOfChoices)

      ballot.weightedUnitVector.combine.zipWithIndex.foreach { case (v, i) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (i == vote.expertId) require(r == stake)
        else require(r == 0)
      }
      ballot.encryptedUnitVector.combine.zipWithIndex.foreach { case (v, i) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (i == vote.expertId) require(r == 1)
        else require(r == 0)
      }
    }
  }
}
