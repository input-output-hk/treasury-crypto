package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.{ElGamalEnc, LiftedElGamalEnc}
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class BallotsSummatorTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.{group, hash}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("voter ballots summation, when voters vote directly") {
    val numberOfExperts = 6
    val numberOfVoters = 10
    val stake = 3
    val voter = new RegularVoter(ctx, numberOfExperts, pubKey, stake)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 1 to numberOfVoters) {
      summator.addVoterBallot(voter.produceVote(0, VotingOptions.Yes))
      summator.addVoterBallot(voter.produceVote(1, VotingOptions.No))
      summator.addVoterBallot(voter.produceVote(2, VotingOptions.Abstain))
    }

    require(summator.getSummedUnitVectors.size == 3)

    summator.getSummedUnitVectors.foreach { case (proposalId, uv) =>
      for(j <- uv.uvDelegations.indices)
        require(LiftedElGamalEnc.decrypt(privKey, uv.uvDelegations(j)).get == 0)
    }

    val uv0 = summator.getSummedUnitVectors(0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0.uvChoices(0)).get == stake*numberOfVoters)
    require(LiftedElGamalEnc.decrypt(privKey, uv0.uvChoices(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0.uvChoices(2)).get == 0)

    val uv1 = summator.getSummedUnitVectors(1)
    require(LiftedElGamalEnc.decrypt(privKey, uv1.uvChoices(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv1.uvChoices(1)).get == stake*numberOfVoters)
    require(LiftedElGamalEnc.decrypt(privKey, uv1.uvChoices(2)).get == 0)

    val uv2 = summator.getSummedUnitVectors(2)
    require(LiftedElGamalEnc.decrypt(privKey, uv2.uvChoices(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2.uvChoices(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2.uvChoices(2)).get == stake*numberOfVoters)
  }

  test("voter ballots summation, when voters delegate") {
    val numberOfExperts = 8
    val numberOfVoters = 13
    val voter = new RegularVoter(ctx, numberOfExperts, pubKey, 2)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 1 to numberOfVoters) {
      summator.addVoterBallot(voter.produceDelegatedVote(0, 0, false))
      summator.addVoterBallot(voter.produceDelegatedVote(10, 5, false))
      summator.addVoterBallot(voter.produceDelegatedVote(22, 7, false))
    }

    require(summator.getSummedUnitVectors.size == 3)

    summator.getSummedUnitVectors.foreach { case (proposalId, uv) =>
      for(j <- uv.uvChoices.indices)
        require(LiftedElGamalEnc.decrypt(privKey, uv.uvChoices(j)).get == 0)
      for(i <- uv.uvDelegations.indices) {
        val res = LiftedElGamalEnc.decrypt(privKey, uv.uvDelegations(i)).get
        proposalId match {
          case 0 if (i == 0) => require(res == (2 * numberOfVoters))
          case 0 => require(res == 0)
          case 10 if (i == 5) => require(res == (2 * numberOfVoters))
          case 10 => require(res == 0)
          case 22 if (i == 7) => require(res == (2 * numberOfVoters))
          case 22 => require(res == 0)
        }
      }
    }
  }

  test("expert ballots summation") {
    val numberOfExperts = 6
    val expert = new Expert(ctx, numberOfExperts, pubKey)
    val summator = new BallotsSummator(ctx, numberOfExperts)

    for(i <- 1 to numberOfExperts) {
      summator.addExpertBallot(expert.produceVote(0, VotingOptions.Yes), 5)
      summator.addExpertBallot(expert.produceVote(1, VotingOptions.No), 5)
      summator.addExpertBallot(expert.produceVote(2, VotingOptions.Abstain), 5)
    }

    require(summator.getSummedUnitVectors.size == 3)

    summator.getSummedUnitVectors.foreach { case (proposalId, uv) =>
      for(j <- uv.uvDelegations.indices)
        require(LiftedElGamalEnc.decrypt(privKey, uv.uvDelegations(j)).get == 0)
    }

    val uv0 = summator.getSummedUnitVectors(0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0.uvChoices(0)).get == 5*numberOfExperts)
    require(LiftedElGamalEnc.decrypt(privKey, uv0.uvChoices(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv0.uvChoices(2)).get == 0)

    val uv1 = summator.getSummedUnitVectors(1)
    require(LiftedElGamalEnc.decrypt(privKey, uv1.uvChoices(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv1.uvChoices(1)).get == 5*numberOfExperts)
    require(LiftedElGamalEnc.decrypt(privKey, uv1.uvChoices(2)).get == 0)

    val uv2 = summator.getSummedUnitVectors(2)
    require(LiftedElGamalEnc.decrypt(privKey, uv2.uvChoices(0)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2.uvChoices(1)).get == 0)
    require(LiftedElGamalEnc.decrypt(privKey, uv2.uvChoices(2)).get == 5*numberOfExperts)
  }
}
