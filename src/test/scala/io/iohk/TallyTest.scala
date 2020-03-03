package io.iohk

import java.math.BigInteger

import org.scalatest.FunSuite
import io.iohk.common.VotingSimulator
import io.iohk.core._
import io.iohk.voting.{Expert, RegularVoter, Tally}

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

    val tallyRes = simulator.doTally(ballots, decryptionShares.map(s => (s._1._2, s._2._2)))

    assert(tallyRes.yes == 6)
    assert(tallyRes.no == 0)
    assert(tallyRes.abstain == 0)
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

    val tallyRes = simulator.doTally(ballots, decryptionShares.map(s => (s._1._2, s._2._2)))

    assert(tallyRes.yes == 150)
    assert(tallyRes.no == 300)
    assert(tallyRes.abstain == 150)
  }
}
