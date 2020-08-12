package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.{DelegatedUniDelegVote, DirectUniDelegVote, UniDelegPublicStakeBallot}
import org.scalatest.FunSuite

class UniDelegBallotsSummatorTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("voter ballots summation, when voters vote directly") {
    val numberOfVoters = 10
    val numberOfExperts = 6
    val numberOfProposals = 2
    val stake = 3
    val pctx = new ApprovalContext(ctx, 3, numberOfExperts, numberOfProposals)
    val summator = new UniDelegBallotsSummator(pctx)

    for(i <- 1 to numberOfVoters) {
      val vote1 = DirectUniDelegVote(List(0,1))
      summator.addVoterBallot(
        UniDelegPublicStakeBallot.createBallot(pctx, vote1, pubKey, stake).get)
    }

    require(summator.getDelegationsSum.get.size == numberOfExperts)
    require(summator.getChoicesSum.get.size == numberOfProposals)
    summator.getChoicesSum.get.foreach(x => require(x.length == 3))

    summator.getDelegationsSum.get.foreach { b =>
      require(LiftedElGamalEnc.decrypt(privKey, b).get == 0)
    }

    val uv0 = summator.getChoicesSum.get(0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(0)).get == stake*numberOfVoters)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0(2)).get == 0)

    val uv1 = summator.getChoicesSum.get(1)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(1)).get == stake*numberOfVoters)
    require(LiftedElGamalEnc.decrypt(privKey, uv1(2)).get == 0)
  }

  test("voter ballots summation, when voters delegate") {
    val numberOfVoters = 10
    val numberOfExperts = 6
    val numberOfProposals = 10
    val stake = 3
    val expertId = 4
    val pctx = new ApprovalContext(ctx, 3, numberOfExperts, numberOfProposals)
    val summator = new UniDelegBallotsSummator(pctx)

    for(i <- 1 to numberOfVoters) {
      summator.addVoterBallot(
        UniDelegPublicStakeBallot.createBallot(pctx, DelegatedUniDelegVote(expertId), pubKey, stake).get)
    }

    require(summator.getDelegationsSum.get.size == numberOfExperts)
    require(summator.getChoicesSum.get.size == numberOfProposals)
    summator.getChoicesSum.get.foreach(x => require(x.length == 3))

    summator.getDelegationsSum.get.zipWithIndex.foreach { case (b, i) =>
      val d = LiftedElGamalEnc.decrypt(privKey, b).get
      if (i == expertId) require(d == numberOfVoters * stake)
      else require(d == 0)
    }

    summator.getChoicesSum.get.foreach { v =>
      v.foreach { b =>
        require(LiftedElGamalEnc.decrypt(privKey, b).get == 0)
      }
    }
  }
}
