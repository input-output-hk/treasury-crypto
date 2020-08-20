package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen._
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.voting.approval.multi_delegation.{MultiDelegExpertBallot, MultiDelegVoterBallot}
import org.scalatest.FunSuite

import scala.util.Random

/**
  * Integration test for all components of the voting protocol: distributed key generation + ballots encryption and voting +
  * tally calculation and decryption
  */
class ProtocolTest extends FunSuite {

  val crs = CryptoContext.generateRandomCRS
  val ctx = new CryptoContext(Option(crs))

  def doTest(votingScenario: VotingSimulator) = {
    val result = votingScenario.runVoting.get
    require(votingScenario.verify(result))
  }

  test("test approval voting with multiple delegation") {
    val scenarios = List(
      new MultiDelegVotingScenario1(ctx),
      new MultiDelegVotingScenario2(ctx),
      new MultiDelegVotingScenario3(ctx),
      new MultiDelegVotingScenario4(ctx))

    scenarios.foreach(doTest(_))
  }
}
