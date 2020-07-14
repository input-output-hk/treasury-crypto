package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class PreferentialExpertBallotTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of ExpertBallot") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialExpertBallot.createPreferentialExpertBallot(pctx, 0, vote, pubKey).get

    require(ballot.verifyBallot(pctx, pubKey))
    ballot.rankVectors.zip(vote.ranking).foreach { case (vector,nonZeroPos) =>
      for(i <- 0 until pctx.numberOfProposals) {
        val bit = LiftedElGamalEnc.decrypt(privKey, vector(i)).get
        if (i == nonZeroPos) require(bit == 1)
        else require(bit == 0)
      }
    }
  }

  test("attempts to create invalid ballots") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val invalidVotes = List(
      DirectPreferentialVote(List(1,10,2,3,4)),
      DirectPreferentialVote(List(1,20,2,3,4)),
      DirectPreferentialVote(List(1,9,2,-1,4)),
      DirectPreferentialVote(List(1,0,2,3,4,5)),
      DirectPreferentialVote(List(1,0,2,3)),
      DirectPreferentialVote(List(1,2,3,4,2)),
    )

    invalidVotes.foreach { v =>
      require(PreferentialExpertBallot.createPreferentialExpertBallot(pctx,0, v, pubKey).isFailure)
    }
  }

  test("invalid ZK proof") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialExpertBallot.createPreferentialExpertBallot(pctx, 0, vote, pubKey).get
    val maliciousBallot = ballot.copy(
      rankVectorsProofs = Some(ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.drop(2))
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  // This test will fail, because the current version of ZK proof does not check duplicates. Restore the test when the proof is improved.
  ignore("the same proposal id should not be duplicated in the ranking list") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialExpertBallot.createPreferentialExpertBallot(pctx, 0, vote, pubKey).get
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head :: ballot.rankVectors.head :: ballot.rankVectors.drop(2),
      rankVectorsProofs = Some(ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.drop(2))
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }
}
