package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.protocol.keygen.Share
import io.iohk.protocol.keygen.datastructures.round5_1.ViolatorsSharesData
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.tally.UniDelegTally.UniDelegStages
import io.iohk.protocol.voting.approval.uni_delegation.{DirectUniDelegVote, UniDelegPublicStakeBallot}
import org.scalatest.FunSuite

class UniDelegTallyRound2Test extends FunSuite with UniDelegTallyTestSetup {

  test("generate UniDelegTallyR2Data when there are no failed members") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tallyR2DataAll.foreach { tallyR2Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR2Data.issuerID).get
      require(tallyR2Data.violatorsShares.isEmpty)
      require(tally.verifyRound2Data(issuerKey, tallyR2Data, dkgR1DataAll).isSuccess)
    }
  }

  test("generate UniDelegTallyR2Data when there are some failed members") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get // exclude 1 R1Data so that we have 1 disqualified member

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tallyR2DataAll.foreach { tallyR2Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR2Data.issuerID).get
      require(tallyR2Data.violatorsShares.size == 1)
      require(tallyR2Data.violatorsShares.head.issuerID == cmIdentifier.getId(committeeKeys.head._2).get)
      require(tally.verifyRound2Data(issuerKey, tallyR2Data, dkgR1DataAll).isSuccess)
    }
  }

  test("verification of UniDelegTallyR2Data") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get // exclude 1 R1Data so that we have 1 disqualified member

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tallyR2DataAll.foreach { tallyR2Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR2Data.issuerID).get
      require(tally.verifyRound2Data(issuerKey, tallyR2Data, dkgR1DataAll).isSuccess)
    }

    val key = committeeKeys.tail.head._2
    val badR2Data = new ViolatorsSharesData(cmIdentifier.getId(key).get, Seq())
    require(tally.verifyRound2Data(key, badR2Data, dkgR1DataAll).isFailure)

    // failed member identifier is used with valid payload
    val badR2Data2 = new ViolatorsSharesData(cmIdentifier.getId(committeeKeys.head._2).get, tallyR2DataAll.head.violatorsShares)
    require(tally.verifyRound2Data(key, badR2Data2, dkgR1DataAll).isFailure)

    // incorrect issuer identifier
    val badR2Data3 = new ViolatorsSharesData(3345, tallyR2DataAll.head.violatorsShares)
    require(tally.verifyRound2Data(key, badR2Data3, dkgR1DataAll).isFailure)

    // bad share
    val validR2Data = tallyR2DataAll.head
    val validShare = validR2Data.violatorsShares.head
    val badShare = Share(validShare.issuerID+1, validShare.share_a, validShare.share_b)
    val badR2Data4 = new ViolatorsSharesData(validR2Data.issuerID, Seq(badShare))
    require(tally.verifyRound2Data(key, badR2Data4, dkgR1DataAll).isFailure)
  }

  test("execution Round 2") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(tallyR2DataAll, expertBallots).isSuccess)
    require(tally.getDelegations.get(0) == numberOfVoters * stake)
    tally.getDelegations.get.tail.foreach(d => require(d == 0))


    require(tally.getAllDisqualifiedCommitteeIds.isEmpty)
    require(tally.getCurrentRound == UniDelegStages.TallyR2)
  }

  test("execution Round 2 when there are not enough decryption shares") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, Seq(tallyR1DataAll.head)).get //simulate that only 1 member submitted R1Data

    require(tally.executeRound2(Seq(), expertBallots).isFailure)
    require(tally.getCurrentRound == UniDelegStages.TallyR1) // should not be updated
  }

  test("execution Round 2 key recovery") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.drop(2).map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.drop(2).map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(tallyR2DataAll, expertBallots).isSuccess)
    require(tally.getDelegations.get(0) == numberOfVoters * stake)
    tally.getDelegations.get.tail.foreach(d => require(d == 0))

    require(tally.getAllDisqualifiedCommitteeIds.size == 2)
    require(tally.getAllDisqualifiedCommitteeIds.contains(cmIdentifier.getId(committeeKeys(0)._2).get))
    require(tally.getAllDisqualifiedCommitteeIds.contains(cmIdentifier.getId(committeeKeys(1)._2).get))
    require(tally.getCurrentRound == UniDelegStages.TallyR2)
  }

  test("execution Round 2 when there are no experts") {
    val pctx = new ApprovalContext(ctx, 3, 0, 2)

    val summator = new UniDelegBallotsSummator(pctx)

    for(i <- 0 until numberOfVoters)
      summator.addVoterBallot(UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(List(0,1)), sharedVotingKey, 2).get)

    val tally = new UniDelegTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    require(tally.executeRound1(summator, tallyR1DataAll).isSuccess)

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(tallyR2DataAll, Seq()).isSuccess)

    require(tally.getDelegations.isEmpty)
    require(tally.getDelegationsSharesSum.isEmpty)
  }

  test("execution Round 2 when there are no expert ballots") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get //simulate that only 1 member submitted R1Data

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(tallyR2DataAll, Seq()).isSuccess)
    require(tally.getDelegations.get(0) == numberOfVoters * stake)
    tally.getDelegations.get.tail.foreach(d => require(d == 0))
    require(tally.getCurrentRound == UniDelegStages.TallyR2)
  }
}
