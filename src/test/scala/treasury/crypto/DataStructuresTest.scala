package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.common.VotingSimulator
import treasury.crypto.keygen.datastructures.C1ShareSerializer

class DataStructuresTest extends FunSuite {

  test("C1Share serialization") {
    val committee = 1
    val voters = 5
    val experts = 5
    val voterStake = 1

    val simulator = new VotingSimulator(committee, experts, voters, voterStake)
    val ballots = simulator.prepareVotersBallots((1, 1), voters - 1, 0, 0) ++ simulator.prepareExpertBallots(0, experts, 0)

    val decryptionSharesBytes = simulator.prepareDecryptionShares(ballots).map { case (deleg, choices) =>
      (deleg.bytes, choices.bytes)
    }

    val decryptionShares = decryptionSharesBytes.map { case (deleg, choices) =>
      (C1ShareSerializer.parseBytes(deleg, simulator.cs).get,
        C1ShareSerializer.parseBytes(choices, simulator.cs).get)
    }

    val verified = simulator.verifyDecryptionShares(ballots, decryptionShares)

    assert(verified)
  }
}
