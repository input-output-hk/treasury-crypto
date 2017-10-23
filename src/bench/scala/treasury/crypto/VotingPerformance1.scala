package treasury.crypto

import org.scalameter.api.{Bench, Gen}
import org.scalatest.{FunSuite, TestSuite}
import treasury.crypto.common.VotingSimulator

//object TallyPerformance extends Bench.LocalTime {
//
////  protected val numberOfVoters = Gen.range("size")(100, 1000, 200)
////  protected val numberOfProjects = 1
////  protected val stakePerVoter = 1
////
////  val simulator = new VotingSimulator(50, 1000, 1, 1)
////  val ballots = simulator.prepareBallots()
////
////  performance of "Tally" in {
////    measure method "perform tally" in {
////      using(numberOfVoters) in {
////        r => 1 + 1
////      }
////    }
////  }
//
//  val voters = Gen.range("Number of Voters")(300, 1500, 300)
//
//  val ranges = for {
//    numberOfVoters <- voters
//  } yield {
//    val simulator = new VotingSimulator(50, 1000, 1, 1)
//    simulator.prepareBallots()
//  }
//
//  performance of "Range" in {
//    measure method "map" in {
//      using(ranges) in {
//        r => 1 + 1
//      }
//    }
//  }
//}

class VotingPerformance1 extends FunSuite {
  test("benchmark tally for different number of voters") {
    val numberOfVoters = (1000 to 5000).by(1000)
    val numberOfExperts = 50

    for (voters <- numberOfVoters) {
      println("Running test for " + voters + " voters and " + numberOfExperts + " experts ...")

      val simulator = new VotingSimulator(50, voters, 1, 1)

      val ballots = Utils.time("     Ballots creation: ", simulator.prepareBallots())

      Utils.time("     Tally: ", simulator.doTally(ballots))
    }
  }
}
