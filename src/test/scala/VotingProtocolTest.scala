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
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(2))
          .produceVote(proposalID, 0, VoteCases.Yes)
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
}
