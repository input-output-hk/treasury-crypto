package io.iohk.protocol.voting.approval

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.multi_delegation.approval.{DelegatedVote, DirectVote}
import io.iohk.protocol.voting.approval.multi_delegation.{BallotSerializer, PublicStakeBallot}
import org.scalatest.FunSuite

class PublicStakeBallotTest extends FunSuite {

  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of ballot") {
    val pctx = new ApprovalContext(ctx, 3, 5)
    val stake = 13

    // test all possible votes
    for (i <- 0 until (pctx.numberOfExperts + pctx.numberOfChoices)) {
      val vote = if (i < pctx.numberOfExperts) DelegatedVote(i) else DirectVote(i - pctx.numberOfExperts)
      val ballot = PublicStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get

      require(ballot.uVector.delegations.size == pctx.numberOfExperts)
      require(ballot.uVector.choice.size == pctx.numberOfChoices)
      require(ballot.uVector.combine.size == pctx.numberOfExperts + pctx.numberOfChoices)

      require(ballot.verifyBallot(pctx, pubKey).isSuccess)
      require(ballot.stake == stake)

      ballot.uVector.combine.zipWithIndex.foreach { case (v,j) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (j == i) require(r == 1)
        else require(r == 0)
      }
    }

    // test invalid votes
    val invalidVotes = Seq(
      DelegatedVote(-1),
      DelegatedVote(pctx.numberOfExperts),
      DelegatedVote(pctx.numberOfExperts + pctx.numberOfChoices),
      DelegatedVote(100),
      DirectVote(-1),
      DirectVote(pctx.numberOfChoices),
      DirectVote(2355))

    for (vote <- invalidVotes) {
      val badBallot = PublicStakeBallot.createBallot(pctx, 0, vote, pubKey, stake)
      require(badBallot.isFailure)
    }
  }

  test("serialization") {
    val pctx = new ApprovalContext(ctx, 3, 5)
    val stake = 13
    val vote = DelegatedVote(2)

    val ballot = PublicStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get
    val bytes = ballot.bytes
    val recoveredBallot = BallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[PublicStakeBallot]

    require(recoveredBallot.proposalId == 0)
    require(recoveredBallot.verifyBallot(pctx, pubKey).isSuccess)

    val ballotWithoutProofs = ballot.copy(uProof = None)
    val recoveredBallot2 = BallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get.asInstanceOf[PublicStakeBallot]
    require(recoveredBallot2.proposalId == 0)
    require(recoveredBallot2.uVector.delegations.size == 5 && recoveredBallot2.uVector.choice.size == 3)
    require(recoveredBallot2.uProof.isEmpty)
  }

  test("serialization when there are no experts") {
    val pctx = new ApprovalContext(ctx, 3, 0)

    val ballot = PublicStakeBallot.createBallot(pctx, 0, DirectVote(1), pubKey, 1).get
    val bytes = ballot.bytes
    val recoveredBallot = BallotSerializer.parseBytes(bytes, Option(ctx.group)).get.asInstanceOf[PublicStakeBallot]

    require(recoveredBallot.verifyBallot(pctx, pubKey).isSuccess)
    require(recoveredBallot.proposalId == 0)
    require(recoveredBallot.uVector.delegations.length == pctx.numberOfExperts)
    require(recoveredBallot.uVector.choice.length == pctx.numberOfChoices)
  }
}
