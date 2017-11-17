package treasury.crypto

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.common.VotingSimulator
import treasury.crypto.core._
import treasury.crypto.voting.{Expert, RegularVoter, Tally}

class TallyTest extends FunSuite {

  test("voting") {
    val committee = 5
    val voters = 2
    val experts = 2
    val voterStake = 3

    val simulator = new VotingSimulator(committee, experts, voters, voterStake)

    val ballots = simulator.prepareVotersBallots((1, 1), 1, 0, 0) ++
                  simulator.prepareExpertBallots(2, 0, 0)
    val decryptionShares = simulator.prepareDecryptionShares(ballots)

    val tallyRes = simulator.doTally(ballots, decryptionShares)

    assert(tallyRes.yes.equals(BigInteger.valueOf(6)))
    assert(tallyRes.no.equals(Zero))
    assert(tallyRes.abstain.equals(Zero))
  }

  test("voting2") {
    val committee = 1
    val voters = 200
    val experts = 50
    val voterStake = 3

    val simulator = new VotingSimulator(committee, experts, voters, voterStake)

    val ballots = simulator.prepareVotersBallots((22, voters/2), voters/4, 0, voters/4) ++
                  simulator.prepareExpertBallots(0, experts, 0)
    val decryptionShares = simulator.prepareDecryptionShares(ballots)

    val tallyRes = simulator.doTally(ballots, decryptionShares)

    assert(tallyRes.yes.equals(BigInteger.valueOf(150)))
    assert(tallyRes.no.equals(BigInteger.valueOf(300)))
    assert(tallyRes.abstain.equals(BigInteger.valueOf(150)))
  }
}
