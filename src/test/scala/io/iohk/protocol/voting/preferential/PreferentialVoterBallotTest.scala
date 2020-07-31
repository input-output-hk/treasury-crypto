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
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 2).get

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

    ballot.delegVector.foreach{ b =>
      val bit = LiftedElGamalEnc.decrypt(privKey, b).get
      require(bit == 0)
    }

    require(1 == LiftedElGamalEnc.decrypt(privKey, ballot.w.get).get)
  }

  test("creation of VoterBallot with delegated vote") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val expertId = 1
    val vote = DelegatedPreferentialVote(expertId)
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 2).get

    require(ballot.verifyBallot(pctx, pubKey))

    ballot.rankVectors.foreach { vector =>
      vector.rank.foreach(b => require(LiftedElGamalEnc.decrypt(privKey, b).get == 0))
      require(LiftedElGamalEnc.decrypt(privKey, vector.z).get == 0)
    }

    require(0 == LiftedElGamalEnc.decrypt(privKey, ballot.w.get).get)

    ballot.delegVector.zipWithIndex.foreach{ case (b,i) =>
      val bit = LiftedElGamalEnc.decrypt(privKey, b).get
      if (i == expertId) require(bit == 1) else require(bit == 0)
    }
  }

  test("creation of VoterBallot when there are no experts") {
    val pctx = new PreferentialContext(ctx, 10, 5, 0)

    require(DelegatedPreferentialVote(0).validate(pctx) == false, "Delegation is impossible")

    val ranking = List(0,1,2,3,4)
    val vote = DirectPreferentialVote(ranking)
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 2).get

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

    require(ballot.delegVector.size == 0)
    require(ballot.delegVectorProof.isEmpty)
    require(ballot.w.isEmpty)
  }

  test("invalid ballots") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val invalidVotes = List(
      DelegatedPreferentialVote(-1),
      DelegatedPreferentialVote(3),
      DirectPreferentialVote(List(1,10,2,3,4)),
      DirectPreferentialVote(List(1,20,2,3,4)),
      DirectPreferentialVote(List(1,9,2,-1,4)),
      DirectPreferentialVote(List(1,0,2,3,4,5)),
      DirectPreferentialVote(List(1,0,2,3)),
      DirectPreferentialVote(List(1,2,3,4,2))
    )

    invalidVotes.foreach { v =>
      require(PreferentialVoterBallot.createBallot(pctx, v, pubKey, 3999).isFailure)
    }
    require(PreferentialVoterBallot.createBallot(pctx, DelegatedPreferentialVote(2), pubKey, 0).isFailure)
    require(PreferentialVoterBallot.createBallot(pctx, DelegatedPreferentialVote(2), pubKey, -1).isFailure)
  }

  test("invalid ZK proof") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DelegatedPreferentialVote(0)
    val ballot = PreferentialVoterBallot.createBallot(pctx,vote, pubKey, 2).get
    val maliciousProof = ballot.rankVectors(1).proof
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head.copy(proof = maliciousProof) :: ballot.rankVectors.tail
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  test("invalid rankVectorsProof") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DelegatedPreferentialVote(0)
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 2).get
    val maliciousProof = ballot.rankVectorsProof.get.copy(T1 = ballot.rankVectorsProof.get.T2)
    val maliciousBallot = ballot.copy(rankVectorsProof = Some(maliciousProof))

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  test("invalid w") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DelegatedPreferentialVote(0)
    val ballot = PreferentialVoterBallot.createBallot(pctx,vote, pubKey, 2).get
    val neg_w = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get / ballot.w.get
    val maliciousBallot = ballot.copy(w = Some(neg_w))
    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)

    val maliciousBallot2 = ballot.copy(w = None)
    require(maliciousBallot2.verifyBallot(pctx, pubKey) == false)
  }

  test("invalid z bit") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DelegatedPreferentialVote(1)
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 2).get
    val neg_z = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get / ballot.rankVectors.head.z
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head.copy(z = neg_z) :: ballot.rankVectors.tail
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  // This test will fail, because the current version of ZK proof does not check duplicates of rank vectors.
  // Restore the test when the proof is improved.
  test("the same proposal id should not be duplicated in the ranking list") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 2).get
    val maliciousBallot = ballot.copy(
      rankVectors = ballot.rankVectors.head :: ballot.rankVectors.head :: ballot.rankVectors.drop(2)
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  test("serialization") {
    val pctx = new PreferentialContext(ctx, 10, 5, 4)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 34).get

    val bytes = ballot.bytes
    val recoveredBallot = PreferentialBallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[PreferentialVoterBallot]

    require(recoveredBallot.stake == 34)
    require(recoveredBallot.verifyBallot(pctx, pubKey))

    val ballotWithoutProofs = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 35, false).get
    val recoveredBallot2 = PreferentialBallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get.asInstanceOf[PreferentialVoterBallot]
    require(recoveredBallot2.stake == 35)
    require(recoveredBallot2.rankVectors.size == pctx.numberOfProposals)
    recoveredBallot2.rankVectors.foreach { rv =>
      require(rv.rank.size == pctx.numberOfRankedProposals)
      require(rv.proof.isEmpty)
    }
    require(recoveredBallot2.delegVector.size == pctx.numberOfExperts)
    require(recoveredBallot2.delegVectorProof.isEmpty)
  }

  test("serialization of ballot when there are no experts") {
    val pctx = new PreferentialContext(ctx, 10, 5, 0)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 34).get

    val bytes = ballot.bytes
    val recoveredBallot = PreferentialBallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[PreferentialVoterBallot]

    require(recoveredBallot.stake == 34)
    require(recoveredBallot.verifyBallot(pctx, pubKey))
    require(recoveredBallot.delegVector.size == 0)
    require(recoveredBallot.delegVectorProof.isEmpty)
    require(recoveredBallot.w.isEmpty)
  }

  test("weightedDelegationVector") {
    val pctx = new PreferentialContext(ctx, 10, 5, 4)

    val vote = DelegatedPreferentialVote(0)
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 34).get

    val weightedDelegVector = ballot.weightedDelegationVector

    weightedDelegVector.tail.foreach { v =>
      require(LiftedElGamalEnc.decrypt(privKey, v).get == 0)
    }
    require(LiftedElGamalEnc.decrypt(privKey, weightedDelegVector.head).get == 34)
  }

  test("weightedRankVectors") {
    val pctx = new PreferentialContext(ctx, 10, 5, 4)

    val ranking = List(0,1,2,3,4)
    val vote = DirectPreferentialVote(ranking)
    val ballot = PreferentialVoterBallot.createBallot(pctx, vote, pubKey, 34).get

    val weightedRankVectors = ballot.weightedRankVectors

    (0 until pctx.numberOfProposals).map { proposalId =>
        ranking.indexOf(proposalId) match {
          case -1 => weightedRankVectors(proposalId).foreach { b =>
            require(LiftedElGamalEnc.decrypt(privKey, b).get == 0)
          }
          case r => (0 until pctx.numberOfRankedProposals).foreach { i =>
            val res = LiftedElGamalEnc.decrypt(privKey, weightedRankVectors(proposalId)(i)).get
            if (i == r) require(res == 34) else require(res == 0)
          }
        }
    }
  }
}
