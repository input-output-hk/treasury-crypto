package treasury.crypto

import org.scalatest.FunSuite

class VotingProtocolTest extends FunSuite {

  test("voting") {
    // Simulating the shared public and private keys of committees
    val cs = new EllipticCurveCryptosystem
    val (privKey, pubKey) = cs.createKeyPair()

    // The parameters of specific voting round
    val proposalID = 1
    val votersNum = 2
    val expertsNum = 2

    val votersBallots =
      for (voterId <- expertsNum until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(3))
          .produceVote(proposalID, 1, VoteCases.Yes)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        new Expert(cs, expertId, expertsNum, pubKey)
          .produceVote(proposalID, 0, VoteCases.Yes)
      }

    val ballots = votersBallots ++ expertsBallots

    // Obtaining results by an arbitrary voter
    val voter = new RegularVoter(cs, 11, expertsNum, pubKey, Array(1))
    val tallyRes = voter.tallyVotes(ballots, privKey)

    assert(tallyRes.yes == 6)
    assert(tallyRes.no == 0)
    assert(tallyRes.abstain == 0)

    val tallyRes2 = voter.tallyVotesV2(ballots, privKey)

    assert(tallyRes2.yes == 6)
    assert(tallyRes2.no == 0)
    assert(tallyRes2.abstain == 0)
  }

  test("voting2") {
    // Simulating the shared public and private keys of committees
    val cs = new EllipticCurveCryptosystem
    val (privKey, pubKey) = cs.createKeyPair()

    val MULTIPLIER = 10

    // The parameters of specific voting round
    val proposalID = 1
    val votersNum = 10 * MULTIPLIER
    val votersDelegatedNum = 20 * MULTIPLIER
    val expertsNum = 5 * MULTIPLIER

    val votersBallots =
      for (voterId <- (expertsNum ) until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(3))
          .produceVote(proposalID, -1, if (voterId % 2 == 1) VoteCases.Yes else VoteCases.Abstain)
      }

    val votersDelegatedBallots =
      for (voterId <- (expertsNum + votersNum) until (expertsNum + votersNum + votersDelegatedNum)) yield {
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(2))
          .produceVote(proposalID, 0, VoteCases.Abstain)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        new Expert(cs, expertId, expertsNum, pubKey)
          .produceVote(proposalID, 0, VoteCases.No)
      }

    val ballots = votersBallots ++ votersDelegatedBallots ++ expertsBallots

    // Obtaining results by an arbitrary voter
    val voter = new RegularVoter(cs, 11, expertsNum, pubKey, Array(1))

    println("Tally started")
    val tallyRes = TimeUtils.time("Tally V1 time: ", voter.tallyVotes(ballots, privKey))

    assert(tallyRes.yes == 15 * MULTIPLIER)
    assert(tallyRes.no == 40 * MULTIPLIER)
    assert(tallyRes.abstain == 15 * MULTIPLIER)

    val tallyRes2 = TimeUtils.time("Tally V2 time: ", voter.tallyVotesV2(ballots, privKey))

    assert(tallyRes2.yes == 15 * MULTIPLIER)
    assert(tallyRes2.no == 40 * MULTIPLIER)
    assert(tallyRes2.abstain == 15 * MULTIPLIER)
  }
}
