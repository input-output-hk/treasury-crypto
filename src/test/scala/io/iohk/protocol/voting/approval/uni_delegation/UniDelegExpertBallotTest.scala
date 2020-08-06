package io.iohk.protocol.voting.approval.uni_delegation

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.ApprovalContext
import org.scalatest.FunSuite

class UniDelegExpertBallotTest extends FunSuite {

  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of UniDelegExpertBallot") {
    val pctx = new ApprovalContext(ctx, 3, 5, 10)
    val stake = 13

    // test all possible votes
    for (i <- 0 until (pctx.numberOfChoices)) {
      val vote = (0 until pctx.numberOfProposals).map(_ => i).toList
      val ballot = UniDelegExpertBallot.createBallot(pctx, 0, DirectUniDelegVote(vote), pubKey).get

      require(ballot.choices.size == pctx.numberOfProposals)
      require(ballot.choicesProofs.get.size == pctx.numberOfProposals)
      require(ballot.verifyBallot(pctx, pubKey))

      ballot.choices.foreach { v =>
        v.zipWithIndex.foreach { case (v, j) =>
          val r = LiftedElGamalEnc.decrypt(privKey, v).get
          if (i == j) require(r == 1)
          else require(r == 0)
        }
      }
    }

    // test invalid votes
    val vote = (0 until pctx.numberOfProposals).map(_ => 0).toList
    val invalidVotes = Seq(-1 +: vote.tail,
                          pctx.numberOfChoices +: vote.tail,
                          100 +: vote.tail,
                          2355 +: vote.tail,
                          vote.drop(1),
                          List())
    for (vote <- invalidVotes) {
      val badBallot = UniDelegExpertBallot.createBallot(pctx, 0, DirectUniDelegVote(vote), pubKey)
      require(badBallot.isFailure)
    }
  }

  test("UniDelegExpertBallot serialization") {
    val pctx = new ApprovalContext(ctx, 3, 5, 10)
    val vote = (0 until pctx.numberOfProposals).map(_ => 0).toList

    val ballot = UniDelegExpertBallot.createBallot(pctx, 0, DirectUniDelegVote(vote), pubKey).get
    val bytes = ballot.bytes
    val recoveredBallot = UniDelegExpertBallotSerializer.parseBytes(bytes, Option(group)).get

    require(recoveredBallot.expertId == 0)
    require(recoveredBallot.choices.size == pctx.numberOfProposals)
    require(recoveredBallot.choicesProofs.get.size == pctx.numberOfProposals)
    require(recoveredBallot.verifyBallot(pctx, pubKey))

    val ballotWithoutProofs = ballot.copy(choicesProofs = None)
    val recoveredBallot2 = UniDelegExpertBallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get
    require(recoveredBallot2.expertId == 0)
    require(recoveredBallot2.choices.size == pctx.numberOfProposals)
    require(recoveredBallot2.choicesProofs.isEmpty)
  }
}
