package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.tally.UniDelegTally.UniDelegStages
import io.iohk.protocol.voting.approval.uni_delegation.{DirectUniDelegVote, UniDelegPublicStakeBallot}
import org.scalatest.FunSuite

class UniDelegTallyRound4Test extends FunSuite with UniDelegTallyTestSetup {

  def prepareTallyRound2() = {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get
  }

  test("generate UniDelegTallyR4Data when there are no failed members") {
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

  test("generate UniDelegTallyR4Data when there are some failed members") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.tail.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.tail.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    tallyR4DataAll.foreach { tallyR4Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR4Data.issuerID).get
      require(tallyR4Data.violatorsShares.size == 1)
      require(tallyR4Data.violatorsShares.head.issuerID == cmIdentifier.getId(committeeKeys.head._2).get)
      require(tally.verifyRound4Data(issuerKey, tallyR4Data, dkgR1DataAll).isSuccess)
    }
  }

  test("verification of UniDelegTallyR4Data") {
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

    require(verifyChoices(tally.getChoices))

    require(tally.getAllDisqualifiedCommitteeIds.isEmpty)
    require(tally.getCurrentRound == UniDelegStages.TallyR4)
  }

  test("execution Round 4 when there are not enough decryption shares") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.tail.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get
    require(tally.getDisqualifiedOnTallyCommitteeIds.size == 1)

    require(tally.executeRound4(Seq()).isFailure)
    require(tally.getCurrentRound == UniDelegStages.TallyR3) // should not be updated
  }

  test("execution Round 4 with key recovery") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.drop(2).map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.drop(2).map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    require(tally.executeRound4(tallyR4DataAll).isSuccess)

    require(tally.getAllDisqualifiedCommitteeIds.size == 2)
    require(tally.getCurrentRound == UniDelegStages.TallyR4)

    require(verifyChoices(tally.getChoices))
  }

  test("execution Round 4 when there are no experts") {
    val pctx = new ApprovalContext(ctx, numberOfChoices,0, 3)
    val summator = new UniDelegBallotsSummator(pctx)
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val vote = List(1,2,0)

    for(i <- 0 until numberOfVoters)
      summator.addVoterBallot(UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(vote), sharedVotingKey, stake).get)

    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    require(tally.executeRound1(summator, tallyR1DataAll).isSuccess)

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(tallyR2DataAll, Seq()).isSuccess)

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    require(tally.executeRound3(tallyR3DataAll).isSuccess)

    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    require(tally.executeRound4(tallyR4DataAll).isSuccess)

    tally.getChoices.zip(vote).foreach { case (v,i) =>
      require(v.size == 3)
      v.zipWithIndex.foreach { case (c,j) =>
        if (i == j) require(c == numberOfVoters * stake)
        else require(c == 0)
      }
    }

    require(tally.getDelegations.isEmpty)
    require(tally.getDelegationsSharesSum.isEmpty)
    require(tally.getCurrentRound == UniDelegStages.TallyR4)
  }
}
