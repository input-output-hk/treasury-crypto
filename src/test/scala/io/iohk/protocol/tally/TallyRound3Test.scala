package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.voting.{Expert, RegularVoter, VotingOptions}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

class TallyRound3Test extends FunSuite{
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

  test("generate TallyR3Data") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(summator, tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)

    val proposalsIds = summator.getDelegationsSum.keySet
    tallyR3DataAll.foreach { r3Data =>
      val pubKey = cmIdentifier.getPubKey(r3Data.issuerID).get
      require(r3Data.decryptionShares.size == proposalsIds.size)
      require(r3Data.decryptionShares.keySet.equals(proposalsIds))
      r3Data.decryptionShares.foreach { case (proposalId, s) =>
        require(proposalsIds.contains(proposalId))
        s.validate(ctx, pubKey, tally.getChoicesSum(proposalId))
      }
    }
  }

  test("verification of TallyR3Data") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(summator, tallyR2DataAll, expertBallots).get

    // verification with correct data and key should succeed
    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    tallyR3DataAll.foreach { r3Data =>
      val pubKey = cmIdentifier.getPubKey(r3Data.issuerID).get
      require(tally.verifyRound3Data(pubKey, r3Data).isSuccess)
    }

    val r3Data = tallyR3DataAll.head
    val pubKey = committeeKeys.head._2
    require(tally.verifyRound3Data(pubKey, r3Data).isSuccess)

    // verification with wrong pubKey should fail
    require(tally.verifyRound3Data(group.createRandomGroupElement.get, tallyR3DataAll.head).isFailure)

    val r3DataBad = r3Data.copy(issuerID = r3Data.issuerID+1)
    require(tally.verifyRound3Data(pubKey, r3DataBad).isFailure)

    val r1DataBad2 = r3Data.copy(decryptionShares = r3Data.decryptionShares - r3Data.decryptionShares.head._1)
    require(tally.verifyRound3Data(pubKey, r1DataBad2).isFailure)

    require(tally.verifyRound3Data(pubKey, r3Data.copy(decryptionShares = Map())).isFailure)
  }

  test("execute Round 3") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(summator, tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    require(tally.executeRound3(tallyR3DataAll).isSuccess)
    require(tally.getDisqualifiedOnTallyCommitteeIds.isEmpty)
    require(tally.getCurrentRound == TallyPhases.TallyR3)

    // at this point we should be able to decrypt choices
    val choices = tally.getChoicesSharesSum.map { case (proposalId, decryptionShare) =>
      val encryptedVector = tally.getChoicesSum(proposalId)
      require(encryptedVector.size == decryptionShare.size)
      val r = for(i <- encryptedVector.indices) yield {
        LiftedElGamalEnc.discreteLog(encryptedVector(i).c2.divide(decryptionShare(i)).get).get
      }
      (proposalId -> r)
    }

    for(i <- 0 until numberOfProposals) {
      require(choices(i)(0) == 2 * numberOfVoters) // all voters and experts in our case voted Yes
      choices(i).tail.foreach(x => require(x == 0))
    }
  }

  test("executeRound3 should do nothing in case there is no ballots") {
    val summator = new BallotsSummator(ctx, numberOfExperts)

    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(summator, tallyR2DataAll, Seq()).get

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    require(tally.executeRound3(tallyR3DataAll).isSuccess)
    require(tally.getChoicesSum.isEmpty)
    require(tally.getChoicesSharesSum.isEmpty)
    require(tally.getCurrentRound == TallyPhases.TallyR3)
  }

  test("executeRound3 should detect failed committee members and disqualify them") {
    val summator = new BallotsSummator(ctx, numberOfExperts)

    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(summator, tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll.tail).get

    require(tally.getDisqualifiedOnTallyCommitteeIds.size == 1)
    require(tally.getDisqualifiedOnTallyCommitteeIds.head == tallyR3DataAll.head.issuerID)
  }
}
