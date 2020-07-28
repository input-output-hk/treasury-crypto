package io.iohk.protocol.voting.preferential.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.tally.TallyTestSetup
import io.iohk.protocol.voting.preferential._
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

import scala.util.Try

class PreferentialTallyTest extends FunSuite with TallyTestSetup {

  test("Full preferential tally test") {

  }
}

object PreferentialTallyTest {

  def generateCommitteeKeys(committeeSize: Int)(implicit group: DiscreteLogGroup): Seq[KeyPair] = {
    for (i <- 0 until committeeSize) yield {
      val privKey = group.createRandomNumber
      (privKey -> group.groupGenerator.pow(privKey).get)
    }
  }
}

trait PreferentialTallyTestSetup {
  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))

  import ctx.group

  val numberOfExperts = 5
  val numberOfVoters = 10
  val stake = 2
  val numberOfProposals = 10
  val numberOfRankedProposals = 5
  val voterRanking = List(2,5,1,9,0)
  val expertRanking = List(3,7,8,9,0)
  val pctx = new PreferentialContext(ctx, numberOfProposals, numberOfRankedProposals, numberOfExperts)

  val committeeKeys = PreferentialTallyTest.generateCommitteeKeys(5)
  val cmIdentifier = new CommitteeIdentifier(committeeKeys.map(_._2))
  val sharedVotingKey = committeeKeys.foldLeft(group.groupIdentity)((acc, key) => acc.multiply(key._2).get)

  val summator = new PreferentialBallotsSummator(pctx)
  for (i <- 0 until numberOfVoters) {
      summator.addVoterBallot(
        PreferentialVoterBallot.createBallot(pctx, DirectPreferentialVote(voterRanking), sharedVotingKey, stake).get)
      summator.addVoterBallot(
        PreferentialVoterBallot.createBallot(pctx, DelegatedPreferentialVote(0), sharedVotingKey, stake).get)
    }
  val expertBallots = for (i <- 0 until numberOfExperts) yield
    PreferentialExpertBallot.createBallot(pctx, i, DirectPreferentialVote(expertRanking), sharedVotingKey).get

  val dkgR1DataAll = committeeKeys.map { keys =>
    val dkg = new DistrKeyGen(ctx, keys, keys._1, keys._1.toByteArray, committeeKeys.map(_._2), cmIdentifier, RoundsData())
    dkg.doRound1().get
  }

  def verifyRankings(rankings: Seq[Seq[BigInt]]): Boolean = Try {
    for(i <- 0 until numberOfProposals) {
      for(j <- 0 until numberOfRankedProposals) {
        val scoreVoter = if (voterRanking.indexOf(i) == j) {
          numberOfVoters * stake
        } else 0
        val scoreExpert = if (expertRanking.indexOf(i) == j) {
          numberOfVoters * stake
        } else 0
        require(rankings(i)(j) == (scoreVoter + scoreExpert))
      }
    }
  }.isSuccess
}
