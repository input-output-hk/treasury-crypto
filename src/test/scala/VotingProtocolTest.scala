import common.VoteCases
import org.scalatest.FunSuite

import scala.collection.mutable.ArrayBuffer

class VotingProtocolTest extends FunSuite {

  test("voting") {

    // Simulating the shared database, where all ballots are stored
    var sharedBallotsList = ArrayBuffer[Ballot]()

    // Simulating the shared public and private keys of committees
    val cs = new EllipticCurveCryptosystem
    val (privKey, pubKey) = cs.createKeyPair()

    // The parameters of specific voting round
    val proposalID = 1
    val expertsNum = 10

    // Simulating the set of experts and voters
    for (voterId <- 1 to 20) // assume the IDs lower or equal to expertsNum (from 1 to 10) - are experts
    {
      val voter = new Voter(cs, voterId, expertsNum, pubKey)
      val voterBallot = voter.produceVote(proposalID, 0, if(voterId % 2 == 0) VoteCases.Yes else VoteCases.No)

      sharedBallotsList += voterBallot
    }

    // Obtaining results by an arbitrary voter
    val voter = new Voter(cs, 0, expertsNum, pubKey)
    voter.tallyVotes(sharedBallotsList, privKey)
  }
}
