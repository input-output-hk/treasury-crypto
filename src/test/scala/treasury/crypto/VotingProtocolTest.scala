package treasury.crypto

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.core._
import treasury.crypto.voting.{Expert, RegularVoter, Tally}

class VotingProtocolTest extends FunSuite {

  test("voting") {
    // Simulating the shared public and private keys of committees
    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair

    // The parameters of specific voting round
    val proposalID = 1
    val votersNum = 2
    val expertsNum = 2

    val votersBallots =
      for (voterId <- expertsNum until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, expertsNum, pubKey, BigInteger.valueOf(3))
          .produceDelegatedVote(proposalID, 1)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        new Expert(cs, expertId, pubKey)
          .produceVote(proposalID, VoteCases.Yes)
      }

    val ballots = votersBallots ++ expertsBallots

    val tallyRes = Tally.countVotes(cs, expertsNum, ballots, privKey)

    assert(tallyRes.yes.equals(BigInteger.valueOf(6)))
    assert(tallyRes.no.equals(Zero))
    assert(tallyRes.abstain.equals(Zero))

    val tallyRes2 = Tally.countVotesV2(cs, ballots, privKey)

    assert(tallyRes2.yes.equals(tallyRes.yes))
    assert(tallyRes2.no.equals(tallyRes.no))
    assert(tallyRes2.abstain.equals(tallyRes.abstain))
  }

  test("voting2") {
    // Simulating the shared public and private keys of committees
    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair

    val MULTIPLIER = 10

    // The parameters of specific voting round
    val proposalID = 1
    val votersNum = 10 * MULTIPLIER
    val votersDelegatedNum = 20 * MULTIPLIER
    val expertsNum = 5 * MULTIPLIER

    val votersBallots =
      for (voterId <- (expertsNum ) until (expertsNum + votersNum)) yield {
        new RegularVoter(cs, expertsNum, pubKey, BigInteger.valueOf(3))
          .produceVote(proposalID, if (voterId % 2 == 1) VoteCases.Yes else VoteCases.Abstain)
      }

    val votersDelegatedBallots =
      for (voterId <- (expertsNum + votersNum) until (expertsNum + votersNum + votersDelegatedNum)) yield {
        new RegularVoter(cs, expertsNum, pubKey, BigInteger.valueOf(2))
          .produceDelegatedVote(proposalID, 0)
      }

    val expertsBallots =
      for (expertId <- 0 until expertsNum) yield {
        new Expert(cs, expertId, pubKey)
          .produceVote(proposalID, VoteCases.No)
      }

    val ballots = votersBallots ++ votersDelegatedBallots ++ expertsBallots

    println("Tally started")
    val tallyRes = TimeUtils.time("Tally V1 time: ", Tally.countVotes(cs, expertsNum, ballots, privKey))

    assert(tallyRes.yes.equals(BigInteger.valueOf(15 * MULTIPLIER)))
    assert(tallyRes.no.equals(BigInteger.valueOf(40 * MULTIPLIER)))
    assert(tallyRes.abstain.equals(BigInteger.valueOf(15 * MULTIPLIER)))

    val tallyRes2 = TimeUtils.time("Tally V2 time: ", Tally.countVotesV2(cs, ballots, privKey))

    assert(tallyRes2.yes.equals(tallyRes.yes))
    assert(tallyRes2.no.equals(tallyRes.no))
    assert(tallyRes2.abstain.equals(tallyRes.abstain))
  }
}
