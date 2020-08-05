package io.iohk.protocol.voting.approval

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.multi_delegation.approval.DirectVote
import io.iohk.protocol.voting.approval.multi_delegation.{BallotSerializer, ExpertBallot}
import org.scalatest.FunSuite

class ExpertBallotTest extends FunSuite {

  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of ExpertBallot") {
    val pctx = new ApprovalContext(ctx, 3, 5)
    val stake = 13

    // test all possible votes
    for (vote <- 0 until (pctx.numberOfChoices)) {
      val ballot = ExpertBallot.createBallot(pctx, 0, 2, DirectVote(vote), pubKey).get

      require(ballot.uChoiceVector.size == pctx.numberOfChoices)
      require(ballot.verifyBallot(pctx, pubKey).isSuccess)

      ballot.uChoiceVector.zipWithIndex.foreach { case (v,i) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (i == vote) require(r == 1)
        else require(r == 0)
      }
    }

    // test invalid votes
    val invalidVotes = Seq(-1, pctx.numberOfChoices, 100, 2355)
    for (vote <- invalidVotes) {
      val badBallot = ExpertBallot.createBallot(pctx, 0, 0, DirectVote(vote), pubKey)
      require(badBallot.isFailure)
    }
  }

  test("ExpertBallot serialization") {
    val pctx = new ApprovalContext(ctx, 3, 5)
    val vote = 2

    val ballot = ExpertBallot.createBallot(pctx, 0, 0, DirectVote(vote), pubKey).get
    val bytes = ballot.bytes
    val recoveredBallot = BallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[ExpertBallot]

    require(recoveredBallot.proposalId == 0)
    require(recoveredBallot.expertId == 0)
    require(recoveredBallot.verifyBallot(pctx, pubKey).isSuccess)

    val ballotWithoutProofs = ballot.copy(uProof = None)
    val recoveredBallot2 = BallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get.asInstanceOf[ExpertBallot]
    require(recoveredBallot2.proposalId == 0)
    require(recoveredBallot2.expertId == 0)
    require(recoveredBallot2.uChoiceVector.size == pctx.numberOfChoices)
    require(recoveredBallot2.uProof.isEmpty)
  }
}
