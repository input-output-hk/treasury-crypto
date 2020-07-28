package io.iohk.protocol.voting.preferential.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.voting.preferential._
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

import scala.util.Try

class PreferentialTallyTest extends FunSuite with PreferentialTallyTestSetup {

  test("Full PreferentialTally integration test") {
    val tally = new PreferentialTally(pctx, cmIdentifier, Map())

    // Each committee member generates PrefTallyR1Data
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)

    // Everyone in the system verifies PrefTallyR1Data from each member
    val verifiedTallyR1DataAll = tallyR1DataAll.filter { r1Data =>
      val pubKey = cmIdentifier.getPubKey(r1Data.issuerID).get
      tally.verifyRound1Data(summator, pubKey, r1Data)
    }

    // Everyone in the system executes Round 1 with a set of verified PrefTallyR1Data from committee members
    tally.executeRound1(summator, verifiedTallyR1DataAll).get

    // Each committee member generates PrefTallyR2Data with recovery shares for the committee members that failed on Round 1
    // (in this test we don't have failed members on Round 1, so PrefTallyR2Data will be empty
    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)

    // Everyone in the system verifies PrefTallyR2Data from each member
    val verifiedTallyR2DataAll = tallyR2DataAll.filter { r2Data =>
      val pubKey = cmIdentifier.getPubKey(r2Data.issuerID).get
      tally.verifyRound2Data(pubKey, r2Data, dkgR1DataAll).isSuccess
    }

    // Everyone in the system executes Round 2 with a set of verified PrefTallyR2Data from committee members
    // After this round we will now how much stake were delegated to each expert
    tally.executeRound2(verifiedTallyR2DataAll, expertBallots).get

    // Each committee member generates PrefTallyR3Data
    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)

    // Everyone in the system verifies PrefTallyR3Data from each member
    val verifiedTallyR3DataAll = tallyR3DataAll.filter { r3Data =>
      val pubKey = cmIdentifier.getPubKey(r3Data.issuerID).get
      tally.verifyRound3Data(pubKey, r3Data).isSuccess
    }

    // Everyone in the system executes Round 3 with a set of verified PrefTallyR3Data from committee members
    tally.executeRound3(verifiedTallyR3DataAll).get

    // Each committee member generates PrefTallyR4Data
    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)

    // Everyone in the system verifies PrefTallyR4Data from each member
    val verifiedTallyR4DataAll = tallyR4DataAll.filter { r4Data =>
      val pubKey = cmIdentifier.getPubKey(r4Data.issuerID).get
      tally.verifyRound4Data(pubKey, r4Data, dkgR1DataAll).isSuccess
    }

    // Everyone in the system executes Round 4 with a set of verified PrefTallyR4Data from committee members
    // After this step tally result will be available for each proposal
    tally.executeRound4(verifiedTallyR4DataAll).get

    val winner = tally.getSortedScores.get.head
    require(winner._1 == 2) // actually both 2 and 3 will have the same score
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

  def verifyScores(scores: Seq[BigInt]): Boolean = Try {
    def score(ranking: List[Int], id: Int) = ranking.indexOf(id) match {
      case -1 => 0
      case n => (pctx.numberOfRankedProposals - n) * numberOfVoters * stake
    }

    for(i <- 0 until numberOfProposals) {
      val votersScore = score(voterRanking, i)
      val expertsScore = score(expertRanking, i)
      require(scores(i) == (votersScore + expertsScore))
    }
  }.isSuccess
}
