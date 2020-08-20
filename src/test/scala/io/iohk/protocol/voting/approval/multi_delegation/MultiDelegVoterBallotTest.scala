package io.iohk.protocol.voting.approval.multi_delegation

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.ApprovalContext
import org.scalatest.FunSuite

class MultiDelegVoterBallotTest extends FunSuite {

  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("VoterBallot interface") {
    val pctx = new ApprovalContext(ctx, 3, 5, 1)
    val stake = 13
    val vote = DelegatedMultiDelegVote(2)

    val ballots = Seq(
      MultiDelegPublicStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get,
      MultiDelegPrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get)

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
