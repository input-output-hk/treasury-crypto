package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.tally.datastructures.TallyR2Data
import io.iohk.protocol.voting.{Expert, RegularVoter, VotingOptions}
import org.scalatest.FunSuite

private class TallyRound2Test extends FunSuite {
  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))

  import ctx.group

  val numberOfExperts = 5
  val numberOfVoters = 3
  val committeeKeys = TallyTest.generateCommitteeKeys(5)
  val cmIdentifier = new CommitteeIdentifier(committeeKeys.map(_._2))
  val sharedVotingKey = committeeKeys.foldLeft(group.groupIdentity)((acc, key) => acc.multiply(key._2).get)

  val voter = new RegularVoter(ctx, numberOfExperts, sharedVotingKey, 1)
  val summator = new BallotsSummator(ctx, numberOfExperts)
  for (i <- 0 until numberOfVoters)
    for (j <- 0 until 3) {
      summator.addVoterBallot(voter.produceVote(j, VotingOptions.Yes))
      summator.addVoterBallot(voter.produceDelegatedVote(j, 0, false))
    }
  val expertBallots = for (i <- 0 until numberOfExperts; j <- 0 until 3) yield {
    new Expert(ctx, i, sharedVotingKey).produceVote(j, VotingOptions.Yes, false)
  }

  val dkgR1DataAll = committeeKeys.map { keys =>
    val dkg = new DistrKeyGen(ctx, keys, keys._1, keys._1.toByteArray, committeeKeys.map(_._2), cmIdentifier, RoundsData())
    dkg.doRound1().get
  }


  test("generate TallyR2Data when there are no failed members") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tallyR2DataAll.foreach { tallyR2Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR2Data.issuerID).get
      require(tallyR2Data.violatorsShares.isEmpty)
      require(tally.verifyRound2Data(issuerKey, tallyR2Data, dkgR1DataAll).isSuccess)
    }
  }

  test("generate TallyR2Data when there are some failed members") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get // exclude 1 R1Data so that we have 1 disqualified member

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tallyR2DataAll.foreach { tallyR2Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR2Data.issuerID).get
      require(tallyR2Data.violatorsShares.size == 1)
      require(tallyR2Data.violatorsShares.head._1 == cmIdentifier.getId(committeeKeys.head._2).get)
      require(tally.verifyRound2Data(issuerKey, tallyR2Data, dkgR1DataAll).isSuccess)
    }
  }

  test("verification of TallyR2Data") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get // exclude 1 R1Data so that we have 1 disqualified member

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tallyR2DataAll.foreach { tallyR2Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR2Data.issuerID).get
      require(tally.verifyRound2Data(issuerKey, tallyR2Data, dkgR1DataAll).isSuccess)
    }

    val key = committeeKeys.tail.head._2
    val badR2Data = TallyR2Data(cmIdentifier.getId(key).get, Array())
    require(tally.verifyRound2Data(key, badR2Data, dkgR1DataAll).isFailure)

    // failed member identifier is used with valid payload
    val badR2Data2 = TallyR2Data(cmIdentifier.getId(committeeKeys.head._2).get, tallyR2DataAll.head.violatorsShares)
    require(tally.verifyRound2Data(key, badR2Data2, dkgR1DataAll).isFailure)

    // incorrect issuer identifier
    val badR2Data3 = TallyR2Data(3345, tallyR2DataAll.head.violatorsShares)
    require(tally.verifyRound2Data(key, badR2Data3, dkgR1DataAll).isFailure)

    // bad share
    val validR2Data = tallyR2DataAll.head
    val validShare = validR2Data.violatorsShares.head
    val badR2Data4 = TallyR2Data(validR2Data.issuerID, Array((validShare._1 + 1, validShare._2)))
    require(tally.verifyRound2Data(key, badR2Data4, dkgR1DataAll).isFailure)
  }

  test("execution Round 2") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(summator, tallyR2DataAll, expertBallots).isSuccess)

    tally.getDelegations.foreach { case (proposalId, delegations) =>
      require(delegations(0) == numberOfVoters)
      delegations.tail.foreach(d => require(d == 0))
    }

    require(tally.getAllDisqualifiedCommitteeIds.isEmpty)
    require(tally.getCurrentRound == TallyPhases.TallyR2)
  }

  test("execution Round 2 when there are not enough decryption shares") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, Seq(tallyR1DataAll.head)).get //simulate that only 1 member submitted R1Data

    require(tally.executeRound2(summator, Seq(), expertBallots).isFailure)
    require(tally.getCurrentRound == TallyPhases.TallyR1) // should not be updated
  }

  test("execution Round 2 key recovery") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get //simulate that only 1 member submitted R1Data

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(summator, tallyR2DataAll, expertBallots).isSuccess)

    tally.getDelegations.foreach { case (proposalId, delegations) =>
      require(delegations(0) == numberOfVoters)
      delegations.tail.foreach(d => require(d == 0))
    }

    require(tally.getAllDisqualifiedCommitteeIds.size == 1)
    require(tally.getAllDisqualifiedCommitteeIds.head == cmIdentifier.getId(committeeKeys.head._2).get)
    require(tally.getCurrentRound == TallyPhases.TallyR2)
  }

  test("execution Round 2 when there are no voter ballots") {
    val summator = new BallotsSummator(ctx, numberOfExperts)
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get //simulate that only 1 member submitted R1Data

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(summator, tallyR2DataAll, expertBallots).isSuccess)

    require(tally.getDelegations.isEmpty)
    require(tally.getCurrentRound == TallyPhases.TallyR2)
  }

  test("execution Round 2 when there are no expert ballots") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.tail.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get //simulate that only 1 member submitted R1Data

    val tallyR2DataAll = committeeKeys.tail.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(summator, tallyR2DataAll, Seq()).isSuccess)

    tally.getDelegations.foreach { case (proposalId, delegations) =>
      require(delegations(0) == numberOfVoters)
      delegations.tail.foreach(d => require(d == 0))
    }
    require(tally.getCurrentRound == TallyPhases.TallyR2)
  }

}