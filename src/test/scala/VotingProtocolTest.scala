import common.VoteCases
import org.scalatest.FunSuite

import scala.collection.mutable.ArrayBuffer

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
      for (voterId <- (expertsNum + 1) to (expertsNum + votersNum)) yield {
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(3))
          .produceVote(proposalID, 1, VoteCases.Yes)
      }

    val expertsBallots =
      for (expertId <- 1 to expertsNum) yield {
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
  }

  test("voting2") {
    // Simulating the shared public and private keys of committees
    val cs = new EllipticCurveCryptosystem
    val (privKey, pubKey) = cs.createKeyPair()

    // The parameters of specific voting round
    val proposalID = 1
    val votersNum = 10
    val votersDelegatedNum = 20
    val expertsNum = 5

    val votersBallots =
      for (voterId <- (expertsNum + 1) to (expertsNum + votersNum)) yield {
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(3))
          .produceVote(proposalID, -1, if (voterId % 2 == 1) VoteCases.Yes else VoteCases.Abstain)
      }

    val votersDelegatedBallots =
      for (voterId <- (expertsNum + votersNum + 1) to (expertsNum + votersNum + votersDelegatedNum)) yield {
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(2))
          .produceVote(proposalID, 0, VoteCases.Abstain)
      }

    val expertsBallots =
      for (expertId <- 1 to expertsNum) yield {
        new Expert(cs, expertId, expertsNum, pubKey)
          .produceVote(proposalID, 0, VoteCases.No)
      }

    val ballots = votersBallots ++ votersDelegatedBallots ++ expertsBallots

    // Obtaining results by an arbitrary voter
    val voter = new RegularVoter(cs, 11, expertsNum, pubKey, Array(1))
    val tallyRes = voter.tallyVotes(ballots, privKey)

    assert(tallyRes.yes == 15)
    assert(tallyRes.no == 40)
    assert(tallyRes.abstain == 15)

    val tallyRes2 = voter.tallyVotesV2(ballots, privKey)

    assert(tallyRes2.yes == 15)
    assert(tallyRes2.no == 40)
    assert(tallyRes2.abstain == 15)
  }
}
