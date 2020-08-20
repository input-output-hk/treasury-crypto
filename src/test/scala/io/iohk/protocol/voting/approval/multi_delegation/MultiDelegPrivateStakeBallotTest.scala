package io.iohk.protocol.voting.approval.multi_delegation

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.ApprovalContext
import org.scalatest.FunSuite

class MultiDelegPrivateStakeBallotTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of ballot") {
    val pctx = new ApprovalContext(ctx, 3, 5, 1)
    val stake = 13

    // test all possible votes
    for (i <- 0 until (pctx.numberOfExperts + pctx.numberOfChoices)) {
      val vote = if (i < pctx.numberOfExperts) DelegatedMultiDelegVote(i) else DirectMultiDelegVote(i - pctx.numberOfExperts)
      val ballot = MultiDelegPrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get

      require(ballot.uVector.delegations.size == pctx.numberOfExperts)
      require(ballot.uVector.choice.size == pctx.numberOfChoices)
      require(ballot.uVector.combine.size == pctx.numberOfExperts + pctx.numberOfChoices)
      require(ballot.vVector.delegations.size == pctx.numberOfExperts)
      require(ballot.vVector.choice.size == pctx.numberOfChoices)
      require(ballot.vVector.combine.size == pctx.numberOfExperts + pctx.numberOfChoices)

      require(ballot.verifyBallot(pctx, pubKey))
      require(LiftedElGamalEnc.decrypt(privKey, ballot.encryptedStake).get == stake)

      ballot.uVector.combine.zipWithIndex.foreach { case (v,j) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (j == i) require(r == 1)
        else require(r == 0)
      }

      ballot.vVector.combine.zipWithIndex.foreach { case (v,j) =>
        val r = LiftedElGamalEnc.decrypt(privKey, v).get
        if (j == i) require(r == stake)
        else require(r == 0)
      }
    }

    // test invalid votes
    val invalidVotes = Seq(
      DelegatedMultiDelegVote(-1),
      DelegatedMultiDelegVote(pctx.numberOfExperts),
      DelegatedMultiDelegVote(pctx.numberOfExperts + pctx.numberOfChoices),
      DelegatedMultiDelegVote(100),
      DirectMultiDelegVote(-1),
      DirectMultiDelegVote(pctx.numberOfChoices),
      DirectMultiDelegVote(2355))

    for (vote <- invalidVotes) {
      val badBallot = MultiDelegPrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake)
      require(badBallot.isFailure)
    }
  }

  test("serialization") {
    val pctx = new ApprovalContext(ctx, 3, 5, 1)
    val stake = 13
    val vote = DelegatedMultiDelegVote(2)

    val ballot = MultiDelegPrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get
    val bytes = ballot.bytes
    val recoveredBallot = MultiDelegBallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[MultiDelegPrivateStakeBallot]

    require(recoveredBallot.proposalId == 0)
    require(recoveredBallot.verifyBallot(pctx, pubKey))

    val ballotWithoutProofs = ballot.copy(uProof = None, vProof = None)
    val recoveredBallot2 = MultiDelegBallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get.asInstanceOf[MultiDelegPrivateStakeBallot]
    require(recoveredBallot2.proposalId == 0)
    require(recoveredBallot2.uVector.delegations.size == 5 && recoveredBallot2.uVector.choice.size == 3)
    require(recoveredBallot2.vVector.delegations.size == 5 && recoveredBallot2.vVector.choice.size == 3)
    require(recoveredBallot2.uProof.isEmpty)
    require(recoveredBallot2.vProof.isEmpty)
  }
}
