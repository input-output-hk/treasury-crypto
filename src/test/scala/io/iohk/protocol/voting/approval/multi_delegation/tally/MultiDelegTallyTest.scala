package io.iohk.protocol.voting.approval.multi_delegation.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.storage.RoundsDataInMemoryStorage
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.{DelegatedMultiDelegVote, DirectMultiDelegVote, MultiDelegExpertBallot, MultiDelegPublicStakeBallot}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite


class MultiDelegTallyTest extends FunSuite with TallyTestSetup {

  test("Full Tally integration test") {
    val tally = new MultiDelegTally(pctx, cmIdentifier, Map())

    // Each committee member generates TallyR1Data
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)

    // Everyone in the system verifies TallyR1Data from each member
    val verifiedTallyR1DataAll = tallyR1DataAll.filter { r1Data =>
      val pubKey = cmIdentifier.getPubKey(r1Data.issuerID).get
      tally.verifyRound1Data(summator, pubKey, r1Data).isSuccess
    }

    // Everyone in the system executes Round 1 with a set of verified TallyR1Data from committee members
    tally.executeRound1(summator, verifiedTallyR1DataAll).get

    // Each committee member generates TallyR2Data with recovery shares for the committee members that failed on Round 1
    // (in this test we don't have failed members on Round 1, so TallyR2Data will be empty
    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)

    // Everyone in the system verifies TallyR1Data from each member
    val verifiedTallyR2DataAll = tallyR2DataAll.filter { r2Data =>
      val pubKey = cmIdentifier.getPubKey(r2Data.issuerID).get
      tally.verifyRound2Data(pubKey, r2Data, dkgR1DataAll).isSuccess
    }

    // Everyone in the system executes Round 2 with a set of verified TallyR2Data from committee members
    // After this round we will now how much stake were delegated to each expert
    tally.executeRound2(verifiedTallyR2DataAll, expertBallots).get

    // Each committee member generates TallyR3Data
    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)

    // Everyone in the system verifies TallyR3Data from each member
    val verifiedTallyR3DataAll = tallyR3DataAll.filter { r3Data =>
      val pubKey = cmIdentifier.getPubKey(r3Data.issuerID).get
      tally.verifyRound3Data(pubKey, r3Data).isSuccess
    }

    // Everyone in the system executes Round 3 with a set of verified TallyR2Data from committee members
    tally.executeRound3(verifiedTallyR3DataAll).get

    // Each committee member generates TallyR4Data
    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)

    // Everyone in the system verifies TallyR4Data from each member
    val verifiedTallyR4DataAll = tallyR4DataAll.filter { r4Data =>
      val pubKey = cmIdentifier.getPubKey(r4Data.issuerID).get
      tally.verifyRound4Data(pubKey, r4Data, dkgR1DataAll).isSuccess
    }

    // Everyone in the system executes Round 4 with a set of verified TallyR4Data from committee members
    // After this step tally result will be available for each proposal
    tally.executeRound4(verifiedTallyR4DataAll).get

    tally.getChoices.foreach { case (proposalId, tallyRes) =>
      require(tallyRes(0) == 2 * numberOfVoters)
      require(tallyRes(1) == 0)
      require(tallyRes(2) == 0)
    }
  }

  test("state recovery") {
    val summator = new MultiDelegBallotsSummator(pctx)

    val tally = new MultiDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll).get

    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)
    tally.executeRound4(tallyR4DataAll).get

    val storage = new RoundsDataInMemoryStorage
    storage.updateDKGr1(dkgR1DataAll).get
    storage.updateTallyR1(tallyR1DataAll).get
    storage.updateTallyR2(tallyR2DataAll).get
    storage.updateTallyR3(tallyR3DataAll).get
    storage.updateTallyR4(tallyR4DataAll).get

    val tallyRecovered0 = MultiDelegTally.recoverState(pctx, cmIdentifier, Map(), MultiDelegTally.Stages.Init, storage, summator).get
    require(tallyRecovered0.getCurrentRound == MultiDelegTally.Stages.Init)

    val tallyRecovered1 = MultiDelegTally.recoverState(pctx, cmIdentifier, Map(), MultiDelegTally.Stages.TallyR1, storage, summator).get
    require(tallyRecovered1.getCurrentRound == MultiDelegTally.Stages.TallyR1)

    val tallyRecovered2 = MultiDelegTally.recoverState(pctx, cmIdentifier, Map(), MultiDelegTally.Stages.TallyR2, storage, summator).get
    require(tallyRecovered2.getCurrentRound == MultiDelegTally.Stages.TallyR2)

    val tallyRecovered3 = MultiDelegTally.recoverState(pctx, cmIdentifier, Map(), MultiDelegTally.Stages.TallyR3, storage, summator).get
    require(tallyRecovered3.getCurrentRound == MultiDelegTally.Stages.TallyR3)

    val tallyRecovered4 = MultiDelegTally.recoverState(pctx, cmIdentifier, Map(), MultiDelegTally.Stages.TallyR4, storage, summator).get
    require(tallyRecovered4.getCurrentRound == MultiDelegTally.Stages.TallyR4)
  }
}

object MultiDelegTallyTest {

  def generateCommitteeKeys(committeeSize: Int)(implicit group: DiscreteLogGroup): Seq[KeyPair] = {
    for (i <- 0 until committeeSize) yield {
      val privKey = group.createRandomNumber
      (privKey -> group.groupGenerator.pow(privKey).get)
    }
  }
}

trait TallyTestSetup {
  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))

  import ctx.group

  val numberOfExperts = 5
  val numberOfVoters = 3
  val numberOfProposals = 3
  val pctx = new ApprovalContext(ctx, 3, numberOfExperts)

  val committeeKeys = MultiDelegTallyTest.generateCommitteeKeys(5)
  val cmIdentifier = new CommitteeIdentifier(committeeKeys.map(_._2))
  val sharedVotingKey = committeeKeys.foldLeft(group.groupIdentity)((acc, key) => acc.multiply(key._2).get)

  val summator = new MultiDelegBallotsSummator(pctx)
  for (i <- 0 until numberOfVoters)
    for (j <- 0 until numberOfProposals) {
      summator.addVoterBallot(
        MultiDelegPublicStakeBallot.createBallot(pctx, j, DirectMultiDelegVote(0), sharedVotingKey, 1, false).get)
      summator.addVoterBallot(
        MultiDelegPublicStakeBallot.createBallot(pctx, j, DelegatedMultiDelegVote(0), sharedVotingKey, 1, false).get)
    }
  val expertBallots = for (i <- 0 until numberOfExperts; j <- 0 until numberOfProposals) yield
    MultiDelegExpertBallot.createBallot(pctx, j, i, DirectMultiDelegVote(0), sharedVotingKey, false).get

  val dkgR1DataAll = committeeKeys.map { keys =>
    val dkg = new DistrKeyGen(ctx, keys, keys._1, keys._1.toByteArray, committeeKeys.map(_._2), cmIdentifier, RoundsData())
    dkg.doRound1().get
  }
}
