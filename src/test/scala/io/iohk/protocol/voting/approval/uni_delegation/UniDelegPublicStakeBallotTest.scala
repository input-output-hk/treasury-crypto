package io.iohk.protocol.voting.approval.uni_delegation

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.ApprovalContext
import org.scalatest.FunSuite

class UniDelegPublicStakeBallotTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of UniDelegPublicStakeBallot with direct vote") {
    val pctx = new ApprovalContext(ctx, 3, 5, 10)

    val vote = DirectUniDelegVote(List(0,0,1,2,0,1,2,0,0,0))
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 2).get

    require(ballot.verifyBallot(pctx, pubKey))
    require(ballot.choiceVectors.size == pctx.numberOfProposals)
    require(ballot.delegationVector.size == pctx.numberOfExperts)

    ballot.choiceVectors.zip(vote.getDirectVote.get).foreach { case (vector,choice) =>
      require(vector.choice.size == pctx.numberOfChoices)
      for(i <- 0 until pctx.numberOfChoices) {
        val bit = LiftedElGamalEnc.decrypt(privKey, vector.choice(i)).get
        if (i == choice) require(bit == 1)
        else require(bit == 0)
      }
    }

    ballot.delegationVector.foreach{ b =>
      val bit = LiftedElGamalEnc.decrypt(privKey, b).get
      require(bit == 0)
    }

    require(1 == LiftedElGamalEnc.decrypt(privKey, ballot.w.get).get)
  }

  test("creation of UniDelegPublicStakeBallot with delegated vote") {
    val pctx = new ApprovalContext(ctx, 3, 5, 10)

    val expertId = 1
    val vote = DelegatedUniDelegVote(expertId)
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 2).get

    require(ballot.verifyBallot(pctx, pubKey))
    require(ballot.choiceVectors.size == pctx.numberOfProposals)
    require(ballot.delegationVector.size == pctx.numberOfExperts)

    ballot.choiceVectors.foreach { vector =>
      vector.choice.foreach(b => require(LiftedElGamalEnc.decrypt(privKey, b).get == 0))
    }

    require(0 == LiftedElGamalEnc.decrypt(privKey, ballot.w.get).get)

    ballot.delegationVector.zipWithIndex.foreach{ case (b,i) =>
      val bit = LiftedElGamalEnc.decrypt(privKey, b).get
      if (i == expertId) require(bit == 1) else require(bit == 0)
    }
  }

  test("creation of UniDelegPublicStakeBallot when there are no experts") {
    val pctx = new ApprovalContext(ctx, 3, 0, 2)

    require(DelegatedUniDelegVote(0).validate(pctx) == false, "Delegation is impossible")

    val choices = List(0,1)
    val vote = DirectUniDelegVote(choices)
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 2).get

    require(ballot.verifyBallot(pctx, pubKey))
    require(ballot.choiceVectors.size == pctx.numberOfProposals)
    require(ballot.delegationVector.size == 0)
    require(ballot.delegationVectorProof.isEmpty)
    require(ballot.w.isEmpty)
  }

  test("invalid ballots") {
    val pctx = new ApprovalContext(ctx, 3, 5, 2)

    val invalidVotes = List(
      DelegatedUniDelegVote(-1),
      DelegatedUniDelegVote(5),
      DirectUniDelegVote(List(-1,0)),
      DirectUniDelegVote(List(1,3)),
      DirectUniDelegVote(List(0,0,0)),
      DirectUniDelegVote(List(0)),
    )

    invalidVotes.foreach { v =>
      require(UniDelegPublicStakeBallot.createBallot(pctx, v, pubKey, 3999).isFailure)
    }
    require(UniDelegPublicStakeBallot.createBallot(pctx, DelegatedUniDelegVote(2), pubKey, 0).isFailure)
    require(UniDelegPublicStakeBallot.createBallot(pctx, DelegatedUniDelegVote(2), pubKey, -1).isFailure)
  }

  test("invalid ZK proof") {
    val pctx = new ApprovalContext(ctx, 3, 3, 2)

    val vote = DelegatedUniDelegVote(0)
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx,vote, pubKey, 2).get
    val maliciousProof = ballot.choiceVectors(1).proof
    val maliciousBallot = ballot.copy(
      choiceVectors = ballot.choiceVectors.head.copy(proof = maliciousProof) :: ballot.choiceVectors.tail
    )

    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)
  }

  test("invalid w") {
    val pctx = new ApprovalContext(ctx, 3, 3, 2)

    val vote = DelegatedUniDelegVote(0)
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx,vote, pubKey, 2).get
    val neg_w = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get / ballot.w.get
    val maliciousBallot = ballot.copy(w = Some(neg_w))
    require(maliciousBallot.verifyBallot(pctx, pubKey) == false)

    val maliciousBallot2 = ballot.copy(w = None)
    require(maliciousBallot2.verifyBallot(pctx, pubKey) == false)
  }


  test("serialization") {
    val pctx = new ApprovalContext(ctx, 3, 5, 2)

    val vote = DirectUniDelegVote(List(0,1))
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 34).get

    val bytes = ballot.bytes
    val recoveredBallot = UniDelegBallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[UniDelegPublicStakeBallot]

    require(recoveredBallot.stake == 34)
    require(recoveredBallot.verifyBallot(pctx, pubKey))

    val ballotWithoutProofs = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 35, false).get
    val recoveredBallot2 = UniDelegBallotSerializer.parseBytes(ballotWithoutProofs.bytes, Option(group)).get.asInstanceOf[UniDelegPublicStakeBallot]
    require(recoveredBallot2.stake == 35)
    require(recoveredBallot2.choiceVectors.size == pctx.numberOfProposals)
    recoveredBallot2.choiceVectors.foreach { rv =>
      require(rv.choice.size == pctx.numberOfChoices)
      require(rv.proof.isEmpty)
    }
    require(recoveredBallot2.delegationVector.size == pctx.numberOfExperts)
    require(recoveredBallot2.delegationVectorProof.isEmpty)
  }

  test("serialization of ballot when there are no experts") {
    val pctx = new ApprovalContext(ctx, 3, 0, 2)

    val choices = List(0,1)
    val vote = DirectUniDelegVote(choices)
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 34).get

    val bytes = ballot.bytes
    val recoveredBallot = UniDelegBallotSerializer.parseBytes(bytes, Option(group)).get.asInstanceOf[UniDelegPublicStakeBallot]

    require(recoveredBallot.stake == 34)
    require(recoveredBallot.verifyBallot(pctx, pubKey))
    require(recoveredBallot.delegationVector.size == 0)
    require(recoveredBallot.delegationVectorProof.isEmpty)
    require(recoveredBallot.w.isEmpty)
  }

  test("weightedDelegationVector") {
    val pctx = new ApprovalContext(ctx, 3, 3, 2)

    val vote = DelegatedUniDelegVote(0)
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 34).get

    val weightedDelegVector = ballot.weightedDelegationVector

    weightedDelegVector.tail.foreach { v =>
      require(LiftedElGamalEnc.decrypt(privKey, v).get == 0)
    }
    require(LiftedElGamalEnc.decrypt(privKey, weightedDelegVector.head).get == 34)
  }

  test("weightedRankVectors") {
    val pctx = new ApprovalContext(ctx, 3, 3, 2)

    val choices = List(0,1)
    val vote = DirectUniDelegVote(choices)
    val ballot = UniDelegPublicStakeBallot.createBallot(pctx, vote, pubKey, 34).get

    val weightedRankVectors = ballot.weightedChoiceVectors

    choices.zip(weightedRankVectors).foreach { case (choice, v) =>
      (0 until pctx.numberOfChoices).foreach { i =>
        val b = LiftedElGamalEnc.decrypt(privKey, v(i)).get
        if (i == choice) require(b == 34)
        else require(b == 0)
      }
    }
  }
}
