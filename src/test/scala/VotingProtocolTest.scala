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
    val expertsNum = 10

    val votersBallots =
      for (voterId <- 11 to 20) yield {
        new RegularVoter(cs, voterId, expertsNum, pubKey, Array(5))
          .produceVote(proposalID, expertsNum, if(voterId % 2 == 0) VoteCases.Yes else VoteCases.No)
      }

    val expertsBallots =
      for (expertId <- 1 to 10) yield {
        new Expert(cs, expertId, expertsNum, pubKey)
          .produceVote(proposalID, 0, if(expertId % 2 == 0) VoteCases.Yes else VoteCases.No)
      }

    val ballots = votersBallots ++ expertsBallots

    // Obtaining results by an arbitrary voter
    val voter = new RegularVoter(cs, 11, expertsNum, pubKey, Array(5))
    voter.tallyVotesV2(ballots, privKey)
  }
}
