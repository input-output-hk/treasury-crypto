package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.voting.ballots.{PrivateStakeBallot, PublicStakeBallot}
import io.iohk.protocol.{CryptoContext, ProtocolContext}
import io.iohk.protocol.voting.{Expert, RegularVoter, VotingOptions}
import org.scalatest.FunSuite

class BallotsSummatorTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("voter ballots summation, when voters vote directly") {
    val numberOfVoters = 10
    val numberOfExperts = 6
    val stake = 3
    val pctx = new ProtocolContext(ctx, 3, numberOfExperts)
    val voter = new RegularVoter(pctx, pubKey, stake)
    val summator = new BallotsSummator(ctx, pctx.numberOfExperts)

    for(i <- 1 to numberOfVoters) {
      summator.addVoterBallot(voter.produceVote(0, VotingOptions.Yes))
      summator.addVoterBallot(voter.produceVote(1, VotingOptions.No))
      summator.addVoterBallot(voter.produceVote(2, VotingOptions.Abstain))
    }

    require(summator.getDelegationsSum.size == 3)
    require(summator.getChoicesSum.size == 3)

    summator.getDelegationsSum.foreach { case (proposalId, uv) =>
      for(j <- uv.indices)
        require(LiftedElGamalEnc.decrypt(privKey, uv(j)).get == 0)
    }

    val uv0 = summator.getChoicesSum(0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(0)).get == stake*numberOfVoters)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(2)).get == 0)

    val uv1 = summator.getChoicesSum(1)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(1)).get == stake*numberOfVoters)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(2)).get == 0)

    val uv2 = summator.getChoicesSum(2)
    require(LiftedElGamalEnc.decrypt(privKey, uv2(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2(2)).get == stake*numberOfVoters)
  }

  test("voter ballots summation, when voters delegate") {
    val numberOfExperts = 8
    val numberOfVoters = 13
    val pctx = new ProtocolContext(ctx, 3, numberOfExperts)
    val voter = new RegularVoter(pctx, pubKey, 2)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 1 to numberOfVoters) {
      summator.addVoterBallot(voter.produceDelegatedVote(0, 0, false))
      summator.addVoterBallot(voter.produceDelegatedVote(10, 5, false))
      summator.addVoterBallot(voter.produceDelegatedVote(22, 7, false))
    }

    require(summator.getDelegationsSum.size == 3)
    require(summator.getChoicesSum.size == 3)

    summator.getChoicesSum.foreach { case (proposalId, uv) =>
      for (j <- uv.indices)
        require(LiftedElGamalEnc.decrypt(privKey, uv(j)).get == 0)
    }

    summator.getDelegationsSum.foreach { case (proposalId, uv) =>
      for(i <- uv.indices) {
        val res = LiftedElGamalEnc.decrypt(privKey, uv(i)).get
        proposalId match {
          case 0 if (i == 0) => require(res == (2 * numberOfVoters))
          case 0 => require(res == 0)
          case 10 if (i == 5) => require(res == (2 * numberOfVoters))
          case 10 => require(res == 0)
          case 22 if (i == 7) => require(res == (2 * numberOfVoters))
          case 22 => require(res == 0)
        }
      }
    }
  }

  test("summation of private stake ballots") {
    val pctx = new ProtocolContext(ctx, 3, 5)
    val summator = new BallotsSummator(ctx, pctx.numberOfExperts)
    val vote = 2
    val stake = 13

    val ballots = for (i <- 0 until 10) yield
      PrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get

    ballots.foreach(summator.addVoterBallot(_))

    require(summator.getChoicesSum.size == 1)
    require(summator.getDelegationsSum.size == 1)

    val fullVector = summator.getDelegationsSum(0) ++ summator.getChoicesSum(0)
    fullVector.zipWithIndex.foreach { case (v, i) =>
      val r = LiftedElGamalEnc.decrypt(privKey, v).get
      if (i == vote) require(r == stake*10)
      else require(r == 0)
    }
  }

  test("summation of private and public stake ballots") {
    val pctx = new ProtocolContext(ctx, 3, 5)
    val summator = new BallotsSummator(ctx, pctx.numberOfExperts)
    val vote = 2
    val stake = 13

    val publicBallots = for (i <- 0 until 10) yield
      PublicStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get
    val privateBallots = for (i <- 0 until 10) yield
      PrivateStakeBallot.createBallot(pctx, 0, vote, pubKey, stake).get

    (publicBallots ++ privateBallots).foreach(summator.addVoterBallot(_))

    require(summator.getChoicesSum.size == 1)
    require(summator.getDelegationsSum.size == 1)

    val fullVector = summator.getDelegationsSum(0) ++ summator.getChoicesSum(0)
    fullVector.zipWithIndex.foreach { case (v, i) =>
      val r = LiftedElGamalEnc.decrypt(privKey, v).get
      if (i == vote) require(r == stake*20)
      else require(r == 0)
    }
  }

  test("expert ballots summation") {
    val numberOfExperts = 6
    val pctx = new ProtocolContext(ctx, 3, numberOfExperts)
    val expert = new Expert(pctx, 0, pubKey)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 1 to numberOfExperts) {
      summator.addExpertBallot(expert.produceVote(0, VotingOptions.Yes), 5)
      summator.addExpertBallot(expert.produceVote(1, VotingOptions.No), 5)
      summator.addExpertBallot(expert.produceVote(2, VotingOptions.Abstain), 5)
    }

    require(summator.getChoicesSum.size == 3)

    summator.getDelegationsSum.foreach { case (proposalId, uv) =>
      for(j <- uv.indices)
        require(LiftedElGamalEnc.decrypt(privKey, uv(j)).get == 0)
    }

    val uv0 = summator.getChoicesSum(0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(0)).get == 5*numberOfExperts)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(2)).get == 0)

    val uv1 = summator.getChoicesSum(1)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(1)).get == 5*numberOfExperts)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(2)).get == 0)

    val uv2 = summator.getChoicesSum(2)
    require(LiftedElGamalEnc.decrypt(privKey, uv2(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2(2)).get == 5*numberOfExperts)
  }
}
