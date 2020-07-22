package io.iohk.protocol.voting.preferential.tally

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.preferential.{DelegatedPreferentialVote, DirectPreferentialVote, PreferentialContext, PreferentialVoterBallot}
import org.scalatest.FunSuite

class PreferentialBallotsSummatorTest extends FunSuite{
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("preferential voter ballots summation, when voters vote directly") {
    val numberOfVoters = 10
    val numberOfExperts = 6
    val numberOfProposals = 10
    val numberOfRankedProposals = 5
    val stake = 3
    val ranking = List(1,5,9,0,2)
    val pctx = new PreferentialContext(ctx, numberOfProposals, numberOfRankedProposals, numberOfExperts)
    val summator = new PreferentialBallotsSummator(pctx)

    for(i <- 1 to numberOfVoters)
      summator.addVoterBallot(
        PreferentialVoterBallot.createBallot(pctx, DirectPreferentialVote(ranking), pubKey, stake).get)

    require(summator.getDelegationsSum.get.size == numberOfExperts)
    require(summator.getRankingsSum.get.size == numberOfProposals)
    summator.getRankingsSum.get.foreach(r => require(r.length == numberOfRankedProposals))

    summator.getDelegationsSum.get.foreach { b =>
      require(LiftedElGamalEnc.decrypt(privKey, b).get == 0)
    }

    summator.getRankingsSum.get.zipWithIndex.foreach { case (rv, proposalId) =>
      val rank = ranking.indexOf(proposalId)
      for (i <- 0 until numberOfRankedProposals) {
        val b = LiftedElGamalEnc.decrypt(privKey, rv(i)).get
        if (i == rank) require(b == numberOfVoters * stake)
        else require(b == 0)
      }
    }
  }

  test("voter ballots summation, when voters delegate") {
    val numberOfVoters = 10
    val numberOfExperts = 6
    val numberOfProposals = 10
    val numberOfRankedProposals = 5
    val stake = 3
    val expertId = 4
    val pctx = new PreferentialContext(ctx, numberOfProposals, numberOfRankedProposals, numberOfExperts)
    val summator = new PreferentialBallotsSummator(pctx)

    for(i <- 1 to numberOfVoters) {
      summator.addVoterBallot(
        PreferentialVoterBallot.createBallot(pctx, DelegatedPreferentialVote(expertId), pubKey, stake).get)
    }

    require(summator.getDelegationsSum.get.size == numberOfExperts)
    require(summator.getRankingsSum.get.size == numberOfProposals)
    summator.getRankingsSum.get.foreach(r => require(r.length == numberOfRankedProposals))

    summator.getDelegationsSum.get.zipWithIndex.foreach { case (b, i) =>
      val d = LiftedElGamalEnc.decrypt(privKey, b).get
      if (i == expertId) require(d == numberOfVoters * stake)
    }

    summator.getRankingsSum.get.foreach { v =>
      v.foreach { b =>
        require(LiftedElGamalEnc.decrypt(privKey, b).get == 0)
      }
    }
  }
}
