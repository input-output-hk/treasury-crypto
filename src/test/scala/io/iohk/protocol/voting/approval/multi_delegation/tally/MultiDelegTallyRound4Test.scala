package io.iohk.protocol.voting.approval.multi_delegation.tally

import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.{DirectMultiDelegVote, MultiDelegPublicStakeBallot}
import io.iohk.protocol.voting.approval.multi_delegation.tally.MultiDelegTally.Stages
import org.scalatest.FunSuite

class MultiDelegTallyRound4Test extends FunSuite with TallyTestSetup {

  // prepare tally initialized to Round 2
  def prepareTallyRound2() = {
    val tally = new MultiDelegTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get
  }

  test("generate TallyR4Data when there are no failed members") {
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
      require(tallyR4Data.violatorsShares.head.issuerID == cmIdentifier.getId(committeeKeys.head._2).get)
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

    tally.getChoices.foreach { case (proposalId, tallyRes) =>
      require(tallyRes(0) == 2 * numberOfVoters)
      require(tallyRes(1) == 0)
      require(tallyRes(2) == 0)
    }

    require(tally.getAllDisqualifiedCommitteeIds.isEmpty)
    require(tally.getCurrentRound == Stages.TallyR4)
  }

  test("execution Round 4 when there are not enough decryption shares") {
    val tally = prepareTallyRound2()

    val tallyR3DataAll = committeeKeys.tail.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get
    require(tally.getDisqualifiedOnTallyCommitteeIds.size == 1)

    require(tally.executeRound4(Seq()).isFailure)
    require(tally.getCurrentRound == Stages.TallyR3) // should not be updated
  }

  test("execution Round 4 with key recovery") {
    val tally = new MultiDelegTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.drop(2).map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.drop(2).map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    require(tally.executeRound4(tallyR4DataAll).isSuccess)

    require(tally.getAllDisqualifiedCommitteeIds.size == 2)
    require(tally.getCurrentRound == Stages.TallyR4)

    tally.getChoices.foreach { case (proposalId, tallyRes) =>
      require(tallyRes(0) == 2 * numberOfVoters)
      require(tallyRes(1) == 0)
      require(tallyRes(2) == 0)
    }
  }

  test("execution Round 4 when there are no voter ballots") {
    val summator = new MultiDelegBallotsSummator(pctx)
    val tally = new MultiDelegTally(pctx, cmIdentifier, Map())

    tally.executeRound1(summator, Seq()).get
    tally.executeRound2(Seq(), Seq()).get
    tally.executeRound3(Seq()).get
    require(tally.executeRound4(Seq()).isSuccess)

    require(tally.getDelegations.isEmpty)
    require(tally.getChoices.isEmpty)
    require(tally.getCurrentRound == Stages.TallyR4)
  }

  test("execution Round 4 when there are no experts") {
    val pctx = new ApprovalContext(ctx, 3, 0, numberOfProposals)
    val tally = new MultiDelegTally(pctx, cmIdentifier, Map())

    val summator = new MultiDelegBallotsSummator(pctx)
    for (i <- 0 until numberOfVoters)
      for (j <- 0 until numberOfProposals) {
        summator.addVoterBallot(
          MultiDelegPublicStakeBallot.createBallot(pctx, j, DirectMultiDelegVote(0), sharedVotingKey, 1, false).get)
      }

    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, Seq()).get

    val tallyR3DataAll = committeeKeys.drop(2).map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.drop(2).map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    require(tally.executeRound4(tallyR4DataAll).isSuccess)

    require(tally.getDelegations.isEmpty)
    require(!tally.getChoices.isEmpty)
    require(tally.getCurrentRound == Stages.TallyR4)

    tally.getChoices.foreach { case (proposalId, tallyRes) =>
      require(tallyRes(0) == numberOfVoters)
      require(tallyRes(1) == 0)
      require(tallyRes(2) == 0)
    }
  }
}
