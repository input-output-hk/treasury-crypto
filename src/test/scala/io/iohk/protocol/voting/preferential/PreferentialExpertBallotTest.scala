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
    val ballot = PreferentialExpertBallot.createBallot(pctx, 0, vote, pubKey).get

    require(ballot.verifyBallot(pctx, pubKey))
    ballot.rankVectors.zipWithIndex.foreach { case (vector,proposalId) =>
      val rank = vote.ranking.indexOf(proposalId)
      for(i <- 0 until pctx.numberOfRankedProposals) {
        val bit = LiftedElGamalEnc.decrypt(privKey, vector.rank(i)).get
        if (i == rank) require(bit == 1)
        else require(bit == 0)
      }
      val z = LiftedElGamalEnc.decrypt(privKey, vector.z).get
      if (rank >= 0) require(z == 0)
      else require(z == 1)
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
      require(PreferentialExpertBallot.createBallot(pctx,0, v, pubKey).isFailure)
    }
  }

  test("invalid ZK proof") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialExpertBallot.createBallot(pctx, 0, vote, pubKey).get
    val maliciousProof = ballot.rankVectors(1).proof
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head.copy(proof = maliciousProof) :: ballot.rankVectors.tail
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  test("invalid z bit") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialExpertBallot.createBallot(pctx, 0, vote, pubKey).get
    val neg_z = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get / ballot.rankVectors.head.z
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head.copy(z = neg_z) :: ballot.rankVectors.tail
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  // This test will fail, because the current version of ZK proof does not check duplicates. Restore the test when the proof is improved.
  test("the same proposal id should not be duplicated in the ranking list") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialExpertBallot.createBallot(pctx, 0, vote, pubKey).get
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head :: ballot.rankVectors.head :: ballot.rankVectors.drop(2)
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  test("serialization") {
    val pctx = new PreferentialContext(ctx, 10, 5, 4)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialExpertBallot.createBallot(pctx, 3, vote, pubKey).get

    val bytes = ballot.bytes
    val recoveredBallot = PreferentialBallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[PreferentialExpertBallot]

    require(recoveredBallot.expertId == 3)
    require(recoveredBallot.verifyBallot(pctx, pubKey))

    val ballotWithoutProofs = PreferentialExpertBallot.createBallot(pctx, 3, vote, pubKey, false).get
    val recoveredBallot2 = PreferentialBallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get.asInstanceOf[PreferentialExpertBallot]
    require(recoveredBallot2.expertId == 3)
    require(recoveredBallot2.rankVectors.size == pctx.numberOfProposals)
    recoveredBallot2.rankVectors.foreach { rv =>
      require(rv.rank.size == pctx.numberOfRankedProposals)
      require(rv.proof.isEmpty)
    }
  }
}
