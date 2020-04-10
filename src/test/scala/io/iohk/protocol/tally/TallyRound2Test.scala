package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.tally.datastructures.TallyR2Data
import io.iohk.protocol.voting.{RegularVoter, VotingOptions}
import org.scalatest.FunSuite

private class TallyRound2Test extends FunSuite {
  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))
  import ctx.group

  val numberOfExperts = 5
  val committeeKeys = TallyTest.generateCommitteeKeys(5)
  val cmIdentifier = new CommitteeIdentifier(committeeKeys.map(_._2))
  val sharedVotingKey = committeeKeys.foldLeft(group.groupIdentity)( (acc,key) => acc.multiply(key._2).get)

  val voter = new RegularVoter(ctx, numberOfExperts, sharedVotingKey, 2)
  val summator = new BallotsSummator(ctx, numberOfExperts)
  for(i <- 0 until 3)
    for(j <- 0 until 3)
      summator.addVoterBallot(voter.produceVote(j, VotingOptions.Yes))

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
    val badR2Data4 = TallyR2Data(validR2Data.issuerID, Array((validShare._1+1, validShare._2)))
    require(tally.verifyRound2Data(key, badR2Data4, dkgR1DataAll).isFailure)
  }
}
