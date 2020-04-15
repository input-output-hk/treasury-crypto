package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.voting.{Expert, RegularVoter, VotingOptions}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

class TallyTest extends FunSuite {
  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))

  import ctx.group

  val numberOfExperts = 5
  val numberOfVoters = 3
  val numberOfProposals = 3

  val committeeKeys = TallyTest.generateCommitteeKeys(5)
  val cmIdentifier = new CommitteeIdentifier(committeeKeys.map(_._2))
  val sharedVotingKey = committeeKeys.foldLeft(group.groupIdentity)((acc, key) => acc.multiply(key._2).get)

  val voter = new RegularVoter(ctx, numberOfExperts, sharedVotingKey, 1)
  val summator = new BallotsSummator(ctx, numberOfExperts)
  for (i <- 0 until numberOfVoters)
    for (j <- 0 until numberOfProposals) {
      summator.addVoterBallot(voter.produceVote(j, VotingOptions.Yes, false))
      summator.addVoterBallot(voter.produceDelegatedVote(j, 0, false))
    }
  val expertBallots = for (i <- 0 until numberOfExperts; j <- 0 until numberOfProposals) yield {
    new Expert(ctx, i, sharedVotingKey).produceVote(j, VotingOptions.Yes, false)
  }

  val dkgR1DataAll = committeeKeys.map { keys =>
    val dkg = new DistrKeyGen(ctx, keys, keys._1, keys._1.toByteArray, committeeKeys.map(_._2), cmIdentifier, RoundsData())
    dkg.doRound1().get
  }

  test("Full Tally integration test") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())

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
    tally.executeRound2(summator, verifiedTallyR2DataAll, expertBallots).get

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
      require(tallyRes.yes == 2 * numberOfVoters)
      require(tallyRes.no == 0)
      require(tallyRes.abstain == 0)
    }
  }
}

object TallyTest {

  def generateCommitteeKeys(committeeSize: Int)(implicit group: DiscreteLogGroup): Seq[KeyPair] = {
    for (i <- 0 until committeeSize) yield {
      val privKey = group.createRandomNumber
      (privKey -> group.groupGenerator.pow(privKey).get)
    }
  }
}
