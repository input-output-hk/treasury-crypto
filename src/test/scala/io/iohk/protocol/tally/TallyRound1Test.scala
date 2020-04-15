package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CommitteeIdentifier
import io.iohk.protocol.tally.datastructures.DecryptionShare
import io.iohk.protocol.voting.{RegularVoter, VotingOptions}

class TallyRound1Test extends TallyTest {
  import ctx.group

  test("generate TallyR1Data") {
    val (privKey, pubKey) = committeeKeys.head
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val r1Data = tally.generateR1Data(summator, (privKey, pubKey)).get
    val proposalsIds = summator.getDelegationsSum.keySet

    require(r1Data.issuerID == cmIdentifier.getId(pubKey).get)
    require(r1Data.decryptionShares.size == numberOfProposals)
    require(r1Data.decryptionShares.keySet.equals(proposalsIds))
    r1Data.decryptionShares.foreach { case (proposalId, s) =>
      require(proposalsIds.contains(proposalId))
      s.validate(ctx, pubKey, summator.getDelegationsSum(proposalId))
    }
  }

  test("verify TallyR1Data") {
    val (privKey, pubKey) = committeeKeys.head
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val r1Data = tally.generateR1Data(summator, (privKey, pubKey)).get

    // verification with correct data and key should succeed
    require(tally.verifyRound1Data(summator, pubKey, r1Data).isSuccess)

    // verification with wrong pubKey should fail
    require(tally.verifyRound1Data(summator, group.createRandomGroupElement.get, r1Data).isFailure)

    val r1DataBad = r1Data.copy(issuerID = r1Data.issuerID+1)
    require(tally.verifyRound1Data(summator, pubKey, r1DataBad).isFailure)

    val r1DataBad2 = r1Data.copy(decryptionShares = r1Data.decryptionShares - r1Data.decryptionShares.head._1)
    require(tally.verifyRound1Data(summator, pubKey, r1DataBad2).isFailure)

    val decrShareBad = (r1Data.decryptionShares(0).proposalId -> DecryptionShare(r1Data.decryptionShares(0).proposalId, r1Data.decryptionShares(1).decryptedC1))
    val r1DataBad3 = r1Data.copy(decryptionShares = r1Data.decryptionShares + decrShareBad)
    require(tally.verifyRound1Data(summator, pubKey, r1DataBad3).isFailure)

    val r1DataBad4 = r1Data.copy(decryptionShares = r1Data.decryptionShares - r1Data.decryptionShares.head._1)
    require(tally.verifyRound1Data(summator, pubKey, r1DataBad4).isFailure)

    require(tally.verifyRound1Data(summator, pubKey, r1Data.copy(decryptionShares = Map())).isFailure)
  }

  test("execute Round 1") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val r1DataAll = committeeKeys.map(keyPair => tally.generateR1Data(summator, keyPair).get)

    require(tally.executeRound1(summator, r1DataAll).isSuccess)

    val delegationsSharesSum = tally.getDelegationsSharesSum

    // at this point we should be able to decrypt delegations because we have all decryption shares
    val delegations = delegationsSharesSum.map { case (proposalId, decryptionShare) =>
      val encryptedVector = summator.getDelegationsSum(proposalId)
      require(encryptedVector.size == decryptionShare.size)
      val r = for(i <- encryptedVector.indices) yield {
        LiftedElGamalEnc.discreteLog(encryptedVector(i).c2.divide(decryptionShare(i)).get).get
      }
      (proposalId -> r)
    }

    for(i <- 0 until numberOfProposals) {
      require(delegations(i)(0) == numberOfVoters) // all voters delegated to the expert 3
      delegations(i).tail.foreach(x => require(x == 0))
    }
  }

  test("executeRound1 should do nothing in case there is no experts") {
    val numberOfExperts = 0
    val numberOfVoters = 5
    val numberOfProposals = 3

    val (privKey, pubKey) = TallyTest.generateCommitteeKeys(1).head
    val committeeIdentifier = new CommitteeIdentifier(Seq(pubKey))
    val voter = new RegularVoter(ctx, numberOfExperts, pubKey, 2)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 0 until numberOfVoters) {
      for(j <- 0 until numberOfProposals) {
        summator.addVoterBallot(voter.produceVote(j, VotingOptions.Yes))
      }
    }

    val tally = new TallyNew(ctx, committeeIdentifier, numberOfExperts, Map())
    val r1Data = tally.generateR1Data(summator, (privKey, pubKey)).get

    require(tally.executeRound1(summator, Seq(r1Data)).isSuccess)
    require(tally.getDelegationsSharesSum.isEmpty)
  }

  test("executeRound1 should do nothing in case there is no ballots") {
    val summator = new BallotsSummator(ctx, numberOfExperts)

    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val r1DataAll = committeeKeys.map(keys => tally.generateR1Data(summator, keys).get)

    require(tally.executeRound1(summator, r1DataAll).isSuccess)
    require(tally.getDelegationsSharesSum.isEmpty)
  }

  test("executeRound1 should detect failed committee members and disqualify them") {
    // test 1 failed committee member
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    val r1DataAll = committeeKeys.map(key => tally.generateR1Data(summator, key).get)
    require(tally.executeRound1(summator, r1DataAll.tail).isSuccess) // we removed r1Data of the first member, so he should be disqualified
    require(tally.getDisqualifiedOnTallyCommitteeIds.size == 1
      && tally.getDisqualifiedOnTallyCommitteeIds.head == cmIdentifier.getId(committeeKeys.head._2).get)

    // test 0 failed committee member
    val tally2 = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    require(tally2.executeRound1(summator, r1DataAll).isSuccess) // we removed r1Data of the first member, so he should be disqualified
    require(tally2.getDisqualifiedOnTallyCommitteeIds.isEmpty)

    // test 1 previously disqualified
    val tally3 = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map(committeeKeys.head._2 -> None))
    require(tally3.executeRound1(summator, r1DataAll).isFailure) // we provided r1Data of disqualified member
    require(tally3.executeRound1(summator, r1DataAll.tail).isSuccess) // now execution should succeed
    require(tally3.getDisqualifiedOnTallyCommitteeIds.isEmpty)
    require(tally3.getAllDisqualifiedCommitteeIds.size == 1)

    // test 1 previously disqualified and 1 new
    val tally4 = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map(committeeKeys.head._2 -> None))
    require(tally4.executeRound1(summator, r1DataAll.drop(2)).isSuccess)
    require(tally4.getDisqualifiedOnTallyCommitteeIds.size == 1
      && tally4.getDisqualifiedOnTallyCommitteeIds.head == cmIdentifier.getId(committeeKeys(1)._2).get)
    require(tally4.getAllDisqualifiedCommitteeIds.size == 2)
  }

  test("executeRound1 should update tally phase properly") {
    val tally = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    require(tally.getCurrentRound == TallyPhases.Init)
    val r1Data = tally.generateR1Data(summator, committeeKeys.head).get
    require(tally.executeRound1(summator, Seq(r1Data)).isSuccess)
    require(tally.executeRound1(summator, Seq(r1Data)).isFailure) // repeated execution should fail
    require(tally.getCurrentRound == TallyPhases.TallyR1)

    val tally2 = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    require(tally2.executeRound1(summator, Seq()).isSuccess) // our single member failed to submit r1Data, but that's fine
    require(tally2.getCurrentRound == TallyPhases.TallyR1) // executeRound1 failed so the phase should not be upcated

    val tally3 = new TallyNew(ctx, cmIdentifier, 0, Map())
    require(tally3.executeRound1(summator, Seq()).isSuccess) // we don't expect r1Data in case there is no experts
    require(tally3.getCurrentRound == TallyPhases.TallyR1)

    val tally4 = new TallyNew(ctx, cmIdentifier, 0, committeeKeys.map(x => (x._2 -> Some(x._1))).toMap)
    require(tally4.executeRound1(summator, Seq()).isSuccess) // all our members were disqualified so we don't expect r1Data
    require(tally4.getCurrentRound == TallyPhases.TallyR1)

    val tally5 = new TallyNew(ctx, cmIdentifier, numberOfExperts, Map())
    require(tally5.executeRound1(summator, Seq(r1Data, r1Data)).isFailure) // we duplicated r1Data, execution should fail
    require(tally5.getCurrentRound == TallyPhases.Init) // executeRound1 failed so the phase should not be updated
  }
}
