package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class PreferentialVoterBallotTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of VoterBallot with direct vote") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialVoterBallot.createPreferentialVoterBallot(pctx, vote, pubKey, 2).get

    require(ballot.verifyBallot(pctx, pubKey))

    ballot.rankVectors.zip(vote.ranking).foreach { case (vector,nonZeroPos) =>
      for(i <- 0 until pctx.numberOfProposals) {
        val bit = LiftedElGamalEnc.decrypt(privKey, vector(i)).get
        if (i == nonZeroPos) require(bit == 1)
        else require(bit == 0)
      }
    }

    ballot.delegVector.foreach{ b =>
      val bit = LiftedElGamalEnc.decrypt(privKey, b).get
      require(bit == 0)
    }

    require(1 == LiftedElGamalEnc.decrypt(privKey, ballot.w).get)
  }

  test("creation of VoterBallot with delegated vote") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val expertId = 1
    val vote = DelegatedPreferentialVote(expertId)
    val ballot = PreferentialVoterBallot.createPreferentialVoterBallot(pctx, vote, pubKey, 2).get

    require(ballot.verifyBallot(pctx, pubKey))

    ballot.rankVectors.foreach { vector =>
      vector.foreach(b => require(LiftedElGamalEnc.decrypt(privKey, b).get == 0))
    }

    require(0 == LiftedElGamalEnc.decrypt(privKey, ballot.w).get)

    ballot.delegVector.zipWithIndex.foreach{ case (b,i) =>
      val bit = LiftedElGamalEnc.decrypt(privKey, b).get
      if (i == expertId) require(bit == 1) else require(bit == 0)
    }
  }

  test("invalid ballots") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val invalidVotes = List(
      DelegatedPreferentialVote(-1),
      DelegatedPreferentialVote(3),
    )

    invalidVotes.foreach { v =>
      require(PreferentialVoterBallot.createPreferentialVoterBallot(pctx, v, pubKey, 3999).isFailure)
    }
    require(PreferentialVoterBallot.createPreferentialVoterBallot(pctx, DelegatedPreferentialVote(2), pubKey, 0).isFailure)
    require(PreferentialVoterBallot.createPreferentialVoterBallot(pctx, DelegatedPreferentialVote(2), pubKey, -1).isFailure)
  }

  test("invalid ZK proof") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DelegatedPreferentialVote(0)
    val ballot = PreferentialVoterBallot.createPreferentialVoterBallot(pctx,vote, pubKey, 2).get
    val maliciousBallot = ballot.copy(
      rankVectorsProofs = Some(ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.drop(2))
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  test("invalid w") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DelegatedPreferentialVote(0)
    val ballot = PreferentialVoterBallot.createPreferentialVoterBallot(pctx,vote, pubKey, 2).get
    val neg_w = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get / ballot.w
    val maliciousBallot = ballot.copy(w = neg_w)

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  // This test will fail, because the current version of ZK proof does not check duplicates of rank vectors.
  // Restore the test when the proof is improved.
  ignore("the same proposal id should not be duplicated in the ranking list") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialVoterBallot.createPreferentialVoterBallot(pctx, vote, pubKey, 2).get
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head :: ballot.rankVectors.head :: ballot.rankVectors.drop(2),
      rankVectorsProofs = Some(ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.head :: ballot.rankVectorsProofs.get.drop(2))
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }
}
