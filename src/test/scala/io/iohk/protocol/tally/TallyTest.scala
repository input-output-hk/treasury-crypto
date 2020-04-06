package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption
import io.iohk.protocol.tally.datastructures.DecryptionShare
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import io.iohk.protocol.voting.{RegularVoter, VotingOptions}
import org.scalatest.FunSuite

class TallyTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get


  test("generate TallyR1Data") {
    val numberOfExperts = 6
    val numberOfVoters = 10
    val numberOfProposals = 3
    val stake = 3

    val committeeIdentifier = new CommitteeIdentifier(Seq(pubKey))
    val voter = new RegularVoter(ctx, numberOfExperts, pubKey, stake)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 1 to numberOfVoters) {
      for(j <- 0 until numberOfProposals) {
        summator.addVoterBallot(voter.produceVote(j, VotingOptions.Yes))
      }
    }

    val tally = new TallyNew(ctx, committeeIdentifier, Map())
    val r1Data = tally.generateR1Data(summator, (privKey, pubKey)).get
    val proposalsIds = summator.getDelegationsSum.keySet

    require(r1Data.issuerID == committeeIdentifier.getId(pubKey).get)
    require(r1Data.decryptionShares.size == numberOfProposals)
    require(r1Data.decryptionShares.keySet.equals(proposalsIds))
    r1Data.decryptionShares.foreach { case (proposalId, s) =>
      require(proposalsIds.contains(proposalId))
      s.validate(ctx, pubKey, summator.getDelegationsSum(proposalId))
    }
  }

  test("verify TallyR1Data") {
    val numberOfExperts = 6
    val numberOfVoters = 10
    val numberOfProposals = 3
    val stake = 3

    val committeeIdentifier = new CommitteeIdentifier(Seq(pubKey))
    val voter = new RegularVoter(ctx, numberOfExperts, pubKey, stake)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 1 to numberOfVoters) {
      for(j <- 0 until numberOfProposals) {
        summator.addVoterBallot(voter.produceVote(j, VotingOptions.Yes))
      }
    }

    val tally = new TallyNew(ctx, committeeIdentifier, Map())
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
}
