package io.iohk.protocol.voting.preferential.tally

import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.voting.preferential.tally.PreferentialTally.PrefStages
import io.iohk.protocol.voting.preferential.{DirectPreferentialVote, PreferentialContext, PreferentialVoterBallot}
import org.scalatest.FunSuite

class PrefTallyRound4Test extends FunSuite with PreferentialTallyTestSetup {
  import ctx.group

  def prepareTallyRound2() = {
    val tally = new PreferentialTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get
  }

  test("generate PrefTallyR4Data when there are no failed members") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    tallyR4DataAll.foreach { tallyR4Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR4Data.issuerID).get
      require(tallyR4Data.violatorsShares.isEmpty)
      require(tally.verifyRound4Data(issuerKey, tallyR4Data, dkgR1DataAll).isSuccess)
    }
  }

  test("generate TallyR4Data when there are some failed members") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.tail.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.tail.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    tallyR4DataAll.foreach { tallyR4Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR4Data.issuerID).get
      require(tallyR4Data.violatorsShares.size == 1)
      require(tallyR4Data.violatorsShares.head._1 == cmIdentifier.getId(committeeKeys.head._2).get)
      require(tally.verifyRound4Data(issuerKey, tallyR4Data, dkgR1DataAll).isSuccess)
    }
  }

  test("verification of TallyR4Data") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.drop(2).map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.drop(2).map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    tallyR4DataAll.foreach { tallyR4Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR4Data.issuerID).get
      require(tally.verifyRound4Data(issuerKey, tallyR4Data, dkgR1DataAll).isSuccess)
      require(tallyR4Data.violatorsShares.size == 2)
    }
  }

  test("execution Round 4") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    require(tally.executeRound4(tallyR4DataAll).isSuccess)

    require(verifyRankings(tally.getRankings))

    require(tally.getAllDisqualifiedCommitteeIds.isEmpty)
    require(tally.getCurrentRound == PrefStages.TallyR4)
  }

  test("execution Round 4 when there are not enough decryption shares") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.tail.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get
    require(tally.getDisqualifiedOnTallyCommitteeIds.size == 1)

    require(tally.executeRound4(Seq()).isFailure)
    require(tally.getCurrentRound == PrefStages.TallyR3) // should not be updated
  }

  test("execution Round 4 with key recovery") {
    val tally = new PreferentialTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.drop(2).map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.drop(2).map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    require(tally.executeRound4(tallyR4DataAll).isSuccess)

    require(tally.getAllDisqualifiedCommitteeIds.size == 2)
    require(tally.getCurrentRound == PrefStages.TallyR4)

    require(verifyRankings(tally.getRankings))
  }

  test("execution Round 4 when there are no experts") {
    val pctx = new PreferentialContext(ctx, numberOfProposals, numberOfRankedProposals, 0)
    val summator = new PreferentialBallotsSummator(pctx)
    val tally = new PreferentialTally(pctx, cmIdentifier, Map())

    for(i <- 0 until numberOfVoters)
      summator.addVoterBallot(PreferentialVoterBallot.createBallot(pctx, DirectPreferentialVote(voterRanking), sharedVotingKey, stake).get)

    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    require(tally.executeRound1(summator, tallyR1DataAll).isSuccess)

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(tallyR2DataAll, Seq()).isSuccess)

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    require(tally.executeRound3(tallyR3DataAll).isSuccess)

    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    require(tally.executeRound4(tallyR4DataAll).isSuccess)

    for(i <- 0 until numberOfProposals) {
      for(j <- 0 until numberOfRankedProposals) {
        val scoreVoter = if (voterRanking.indexOf(i) == j) {
          numberOfVoters * stake
        } else 0
        val res = LiftedElGamalEnc.discreteLog(
          tally.getRankingsSum(i)(j).c2.divide(tally.getRankingsSharesSum(i)(j)).get).get
        require(res == scoreVoter)
      }
    }

    require(tally.getDelegations.isEmpty)
    require(tally.getDelegationsSharesSum.isEmpty)
    require(tally.getCurrentRound == PrefStages.TallyR4)
  }
}
