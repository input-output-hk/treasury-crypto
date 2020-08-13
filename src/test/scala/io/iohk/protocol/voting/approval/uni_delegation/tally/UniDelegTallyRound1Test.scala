package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CommitteeIdentifier
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.tally.UniDelegTally.UniDelegStages
import io.iohk.protocol.voting.approval.uni_delegation.{DirectUniDelegVote, UniDelegPublicStakeBallot}
import org.scalatest.FunSuite

class UniDelegTallyRound1Test extends FunSuite with UniDelegTallyTestSetup {
  import ctx.group

  test("generate UniDelegTallyR1Data") {
    val (privKey, pubKey) = committeeKeys.head
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val r1Data = tally.generateR1Data(summator, (privKey, pubKey)).get

    require(r1Data.issuerID == cmIdentifier.getId(pubKey).get)
    require(r1Data.delegDecryptedC1.size == numberOfExperts)
    require(r1Data.validate(ctx, pubKey, summator.getDelegationsSum.get))
  }

  test("verify UniDelegTallyR1Data") {
    val (privKey, pubKey) = committeeKeys.head
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val r1Data = tally.generateR1Data(summator, (privKey, pubKey)).get

    // verification with correct data and key should succeed
    require(tally.verifyRound1Data(summator, pubKey, r1Data))

    // verification with wrong pubKey should fail
    require(tally.verifyRound1Data(summator, group.createRandomGroupElement.get, r1Data) == false)

    val r1DataBad = r1Data.copy(issuerID = r1Data.issuerID+1)
    require(tally.verifyRound1Data(summator, pubKey, r1DataBad) == false)

    val r1DataBad2 = r1Data.copy(delegDecryptedC1 = r1Data.delegDecryptedC1.tail)
    require(tally.verifyRound1Data(summator, pubKey, r1DataBad2) == false)

    val decrShareBad = r1Data.delegDecryptedC1(2) +: r1Data.delegDecryptedC1.tail
    val r1DataBad3 = r1Data.copy(delegDecryptedC1 = decrShareBad)
    require(tally.verifyRound1Data(summator, pubKey, r1DataBad3) == false)

    require(tally.verifyRound1Data(summator, pubKey, r1Data.copy(delegDecryptedC1 = Vector())) == false)
  }

  test("execute Round 1") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val r1DataAll = committeeKeys.map(keyPair => tally.generateR1Data(summator, keyPair).get)

    require(tally.executeRound1(summator, r1DataAll).isSuccess)

    val delegationsSharesSum = tally.getDelegationsSharesSum.get
    val delegationsSum = summator.getDelegationsSum.get
    require(delegationsSharesSum.size == delegationsSum.size)

    // at this point we should be able to decrypt delegations because we have all decryption shares
    val delegations = for(i <- delegationsSum.indices) yield {
      LiftedElGamalEnc.discreteLog(delegationsSum(i).c2.divide(delegationsSharesSum(i)).get).get
    }

    require(delegations(0) == numberOfVoters * stake) // all voters delegated to the expert 0
    delegations.tail.foreach(x => require(x == 0))
  }

  test("executeRound1 should do nothing in case there is no experts") {
    val numberOfExperts = 0
    val numberOfVoters = 5
    val pctx = new ApprovalContext(ctx,  numberOfChoices, numberOfExperts, numberOfProposals)

    val (privKey, pubKey) = UniDelegTallyTest.generateCommitteeKeys(1).head
    val committeeIdentifier = new CommitteeIdentifier(Seq(pubKey))
    val summator = new UniDelegBallotsSummator(pctx)

    for(i <- 0 until numberOfVoters)
      summator.addVoterBallot(UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(voterChoices), pubKey, 2).get)

    val tally = new UniDelegTally(pctx, committeeIdentifier, Map())
    val r1Data = tally.generateR1Data(summator, (privKey, pubKey)).get

    require(tally.executeRound1(summator, Seq(r1Data)).isSuccess)
    require(tally.getDelegationsSharesSum.isEmpty)
  }

  test("executeRound1 should do nothing in case there is no ballots") {
    val summator = new UniDelegBallotsSummator(pctx)

    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val r1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)

    require(tally.executeRound1(summator, r1DataAll).isFailure)
    require(tally.getDelegationsSharesSum.isEmpty)
  }

  test("executeRound1 should detect failed committee members and disqualify them") {
    // test 1 failed committee member
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    val r1DataAll = committeeKeys.map(key => tally.generateR1Data(summator, key).get)
    require(tally.executeRound1(summator, r1DataAll.tail).isSuccess) // we removed r1Data of the first member, so he should be disqualified
    require(tally.getDisqualifiedOnTallyCommitteeIds.size == 1
      && tally.getDisqualifiedOnTallyCommitteeIds.head == cmIdentifier.getId(committeeKeys.head._2).get)

    // test 0 failed committee member
    val tally2 = new UniDelegTally(pctx, cmIdentifier, Map())
    require(tally2.executeRound1(summator, r1DataAll).isSuccess) // we removed r1Data of the first member, so he should be disqualified
    require(tally2.getDisqualifiedOnTallyCommitteeIds.isEmpty)

    // test 1 previously disqualified
    val tally3 = new UniDelegTally(pctx, cmIdentifier, Map(committeeKeys.head._2 -> None))
    require(tally3.executeRound1(summator, r1DataAll).isFailure) // we provided r1Data of disqualified member
    require(tally3.executeRound1(summator, r1DataAll.tail).isSuccess) // now execution should succeed
    require(tally3.getDisqualifiedOnTallyCommitteeIds.isEmpty)
    require(tally3.getAllDisqualifiedCommitteeIds.size == 1)

    // test 1 previously disqualified and 1 new
    val tally4 = new UniDelegTally(pctx, cmIdentifier, Map(committeeKeys.head._2 -> None))
    require(tally4.executeRound1(summator, r1DataAll.drop(2)).isSuccess)
    require(tally4.getDisqualifiedOnTallyCommitteeIds.size == 1
      && tally4.getDisqualifiedOnTallyCommitteeIds.head == cmIdentifier.getId(committeeKeys(1)._2).get)
    require(tally4.getAllDisqualifiedCommitteeIds.size == 2)
  }

  test("executeRound1 should update tally phase properly") {
    val tally = new UniDelegTally(pctx, cmIdentifier, Map())
    require(tally.getCurrentRound == UniDelegStages.Init)
    val r1Data = tally.generateR1Data(summator, committeeKeys.head).get
    require(tally.executeRound1(summator, Seq(r1Data)).isSuccess)
    require(tally.executeRound1(summator, Seq(r1Data)).isFailure) // repeated execution should fail
    require(tally.getCurrentRound == UniDelegStages.TallyR1)

    val tally2 = new UniDelegTally(pctx, cmIdentifier, Map())
    require(tally2.executeRound1(summator, Seq()).isSuccess) // our single member failed to submit r1Data, but that's fine
    require(tally2.getCurrentRound == UniDelegStages.TallyR1) // executeRound1 failed so the phase should not be upcated

    val tally3 = new UniDelegTally(new ApprovalContext(ctx, numberOfChoices, 0, numberOfProposals), cmIdentifier, Map())
    require(tally3.executeRound1(summator, Seq()).isSuccess) // we don't expect r1Data in case there is no experts
    require(tally3.getCurrentRound == UniDelegStages.TallyR1)

    val tally4 = new UniDelegTally(new ApprovalContext(ctx, numberOfChoices, 0, numberOfProposals), cmIdentifier, committeeKeys.map(x => (x._2 -> Some(x._1))).toMap)
    require(tally4.executeRound1(summator, Seq()).isSuccess) // all our members were disqualified so we don't expect r1Data
    require(tally4.getCurrentRound == UniDelegStages.TallyR1)

    val tally5 = new UniDelegTally(pctx, cmIdentifier, Map())
    require(tally5.executeRound1(summator, Seq(r1Data, r1Data)).isFailure) // we duplicated r1Data, execution should fail
    require(tally5.getCurrentRound == UniDelegStages.Init) // executeRound1 failed so the phase should not be updated
  }
}
