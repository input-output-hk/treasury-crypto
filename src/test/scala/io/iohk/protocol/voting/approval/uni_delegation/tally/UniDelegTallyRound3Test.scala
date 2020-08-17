package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.tally.UniDelegTally.UniDelegStages
import io.iohk.protocol.voting.approval.uni_delegation.{DirectUniDelegVote, UniDelegPublicStakeBallot}
import org.scalatest.FunSuite

class UniDelegTallyRound3Test extends FunSuite with UniDelegTallyTestSetup {
  import ctx.group

  test("generate UniDelegTallyR3Data") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    tallyR3DataAll.foreach { tallyR3Data =>
      val issuerKey = cmIdentifier.getPubKey(tallyR3Data.issuerID).get
      require(tallyR3Data.choicesDecryptedC1.length == pctx.numberOfProposals)
      require(tally.verifyRound3Data(issuerKey, tallyR3Data).isSuccess)
      require(tallyR3Data.validate(pctx.cryptoContext, issuerKey, tally.getChoicesSum))
    }
  }

  test("verification of UniDelegTallyR3Data") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

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

    val r3DataBad2 = r3Data.copy(choicesDecryptedC1 = r3Data.choicesDecryptedC1.tail)
    require(tally.verifyRound3Data(pubKey, r3DataBad2).isFailure)

    require(tally.verifyRound3Data(pubKey, r3Data.copy(choicesDecryptedC1 = List())).isFailure)
  }

  test("execute Round 3") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

    // verification with correct data and key should succeed
    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    require(tally.executeRound3(tallyR3DataAll).isSuccess)
    require(tally.getDisqualifiedOnTallyCommitteeIds.isEmpty)
    require(tally.getCurrentRound == UniDelegStages.TallyR3)

    // at this point we should be able to decrypt rankings
    val choices = tally.getChoicesSharesSum.zip(tally.getChoicesSum).map {
      case (decryptionShares, encryptedVector) =>
        require(encryptedVector.size == decryptionShares.size)
        for(i <- encryptedVector.indices) yield {
          LiftedElGamalEnc.discreteLog(encryptedVector(i).c2.divide(decryptionShares(i)).get).get
        }
    }

    choices.foreach { v =>
      require(v.size == numberOfChoices)
      require(v(0) == 0)
      require(v(1) == numberOfVoters * stake)
      require(v(2) == numberOfVoters * stake)
    }
  }

  test("executeRound3 should detect failed committee members and disqualify them") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    tally.executeRound1(summator, tallyR1DataAll).get

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    tally.executeRound2(tallyR2DataAll, expertBallots).get

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    tally.executeRound3(tallyR3DataAll.tail).get

    require(tally.getDisqualifiedOnTallyCommitteeIds.size == 1)
    require(tally.getDisqualifiedOnTallyCommitteeIds.head == tallyR3DataAll.head.issuerID)
  }

  test("execution Round 3 when there are no experts") {
    val pctx = new ApprovalContext(ctx, numberOfChoices, 0,2)

    val summator = new UniDelegBallotsSummator(pctx)

    for(i <- 0 until numberOfVoters)
      summator.addVoterBallot(UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(List(1,1)), sharedVotingKey, stake).get)

    val tally = new UniDelegTally(pctx, cmIdentifier, Map())

    val tallyR1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)
    require(tally.executeRound1(summator, tallyR1DataAll).isSuccess)

    val tallyR2DataAll = committeeKeys.map(keys => tally.generateR2Data(keys, dkgR1DataAll).get)
    require(tally.executeRound2(tallyR2DataAll, Seq()).isSuccess)

    val tallyR3DataAll = committeeKeys.map(keys => tally.generateR3Data(keys).get)
    require(tally.executeRound3(tallyR3DataAll).isSuccess)

    require(tally.getDelegations.isEmpty)
    require(tally.getDelegationsSharesSum.isEmpty)

    val choices = tally.getChoicesSharesSum.zip(tally.getChoicesSum).map {
      case (decryptionShares, encryptedVector) =>
        require(encryptedVector.size == decryptionShares.size)
        for(i <- encryptedVector.indices) yield {
          LiftedElGamalEnc.discreteLog(encryptedVector(i).c2.divide(decryptionShares(i)).get).get
        }
    }

    choices.foreach { v =>
      require(v.size == numberOfChoices)
      require(v(0) == 0)
      require(v(1) == numberOfVoters * stake)
      require(v(2) == 0)
    }
  }
}
