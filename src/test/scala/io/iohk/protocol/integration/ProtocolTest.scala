package io.iohk.protocol.integration

import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

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

  test("test approval voting with uni delegation") {
    val scenarios = List(
      new UniDelegVotingScenario1(ctx),
      new UniDelegVotingScenario2(ctx))

    scenarios.foreach(doTest(_))
  }

  test("test preferential voting") {
    val scenarios = List(
      new PreferentialVotingScenario1(ctx),
      new PreferentialVotingScenario2(ctx))

    scenarios.foreach(doTest(_))
  }
}
