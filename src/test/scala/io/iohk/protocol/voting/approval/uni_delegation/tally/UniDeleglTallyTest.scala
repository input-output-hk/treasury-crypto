package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.{DelegatedUniDelegVote, DirectUniDelegVote, UniDelegExpertBallot, UniDelegPublicStakeBallot}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

import scala.util.Try

class UniDelegTallyTest extends FunSuite with UniDelegTallyTestSetup {

  test("Full UniDelegTally integration test") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())

    // Each committee member generates UniDelegTallyR1Data
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)

    // Everyone in the system verifies UniDelegTallyR1Data from each member
    val verifiedTallyR1DataAll = tallyR1DataAll.filter { r1Data =>
      val pubKey = cmIdentifier.getPubKey(r1Data.issuerID).get
      tally.verifyRound1Data(summator, pubKey, r1Data)
    }

    // Everyone in the system executes Round 1 with a set of verified UniDelegTallyR1Data from committee members
    tally.executeRound1(summator, verifiedTallyR1DataAll).get

    // Each committee member generates UniDelegTallyR2Data with recovery shares for the committee members that failed on Round 1
    // (in this test we don't have failed members on Round 1, so UniDelegTallyR2Data will be empty
    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)

    // Everyone in the system verifies UniDelegTallyR2Data from each member
    val verifiedTallyR2DataAll = tallyR2DataAll.filter { r2Data =>
      val pubKey = cmIdentifier.getPubKey(r2Data.issuerID).get
      tally.verifyRound2Data(pubKey, r2Data, dkgR1DataAll).isSuccess
    }

    // Everyone in the system executes Round 2 with a set of verified UniDelegTallyR2Data from committee members
    // After this round we will now how much stake were delegated to each expert
    tally.executeRound2(verifiedTallyR2DataAll, expertBallots).get

    // Each committee member generates UniDelegTallyR3Data
    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)

    // Everyone in the system verifies UniDelegTallyR3Data from each member
    val verifiedTallyR3DataAll = tallyR3DataAll.filter { r3Data =>
      val pubKey = cmIdentifier.getPubKey(r3Data.issuerID).get
      tally.verifyRound3Data(pubKey, r3Data).isSuccess
    }

    // Everyone in the system executes Round 3 with a set of verified UniDelegTallyR3Data from committee members
    tally.executeRound3(verifiedTallyR3DataAll).get

    // Each committee member generates UniDelegTallyR4Data
    val tallyR4DataAll = committeeKeys.map(keys => tally.generateR4Data(keys, dkgR1DataAll).get)

    // Everyone in the system verifies UniDelegTallyR4Data from each member
    val verifiedTallyR4DataAll = tallyR4DataAll.filter { r4Data =>
      val pubKey = cmIdentifier.getPubKey(r4Data.issuerID).get
      tally.verifyRound4Data(pubKey, r4Data, dkgR1DataAll).isSuccess
    }

    // Everyone in the system executes Round 4 with a set of verified UniDelegTallyR4Data from committee members
    // After this step tally result will be available for each proposal
    tally.executeRound4(verifiedTallyR4DataAll).get

    // tally result will be a list of vectors for each proposal. The vector contains the number of votes for each voting option
    val tallyResult = tally.getChoices
    require(verifyChoices(tallyResult))
  }
}

object UniDelegTallyTest {

  def generateCommitteeKeys(committeeSize: Int)(implicit group: DiscreteLogGroup): Seq[KeyPair] = {
    for (i <- 0 until committeeSize) yield {
      val privKey = group.createRandomNumber
      (privKey -> group.groupGenerator.pow(privKey).get)
    }
  }
}

trait UniDelegTallyTestSetup {
  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))

  import ctx.group

  val numberOfExperts = 5
  val numberOfVoters = 10
  val stake = 2
  val numberOfProposals = 10
  val numberOfChoices = 3
  val voterChoices = List.fill[Int](numberOfProposals)(1)
  val expertChoices = List.fill[Int](numberOfProposals)(2)
  val pctx = new ApprovalContext(ctx, numberOfChoices, numberOfExperts, numberOfProposals)

  val committeeKeys = UniDelegTallyTest.generateCommitteeKeys(5)
  val cmIdentifier = new CommitteeIdentifier(committeeKeys.map(_._2))
  val sharedVotingKey = committeeKeys.foldLeft(group.groupIdentity)((acc, key) => acc.multiply(key._2).get)

  val summator = new UniDelegBallotsSummator(pctx)
  for (i <- 0 until numberOfVoters) {
      summator.addVoterBallot(
        UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(voterChoices), sharedVotingKey, stake).get)
      summator.addVoterBallot(
        UniDelegPublicStakeBallot.createBallot(pctx, DelegatedUniDelegVote(0), sharedVotingKey, stake).get)
    }
  val expertBallots = for (i <- 0 until numberOfExperts) yield
    UniDelegExpertBallot.createBallot(pctx, i, DirectUniDelegVote(expertChoices), sharedVotingKey).get

  val dkgR1DataAll = committeeKeys.map { keys =>
    val dkg = new DistrKeyGen(ctx, keys, keys._1, keys._1.toByteArray, committeeKeys.map(_._2), cmIdentifier, RoundsData())
    dkg.doRound1().get
  }

  def verifyChoices(choices: List[Vector[BigInt]]): Boolean = Try {
    require(choices.size == numberOfProposals)
    choices.foreach { v =>
      require(v.size == numberOfChoices)
      require(v(0) == 0)
      require(v(1) == numberOfVoters * stake)
      require(v(2) == numberOfVoters * stake)
    }
  }.isSuccess
}
