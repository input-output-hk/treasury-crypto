package io.iohk.core.crypto

import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import org.scalameter.picklers.noPickler._
import org.scalameter.{Bench, Gen}

object DiscreteLogBench extends Bench.ForkedTime {

  case class TestData(dlogGroup: DiscreteLogGroup, exponent: BigInt) {
    val point = dlogGroup.groupGenerator.pow(exponent)(dlogGroup).get
  }

  //val dlogGroupGen = Gen.enumeration("dlog group")(AvailableGroups.values.toSeq:_*)
  val dlogGroupGen = Gen.enumeration("dlog group")(AvailableGroups.OpenSSL_secp256k1)
  val exponentsGen = Gen.enumeration("exponent")(BigInt(1048576))
  val testDataGen =
    for (group <- dlogGroupGen;
         exponent <- exponentsGen)
      yield TestData(DiscreteLogGroupFactory.constructDlogGroup(group).get, exponent)

  performance of "LiftedElGamalEnc" in {

    measure method "discreteLog" in {
      using(testDataGen) in { testData: TestData =>
        implicit val dlog = testData.dlogGroup
        require(LiftedElGamalEnc.discreteLog(testData.point).get == testData.exponent)
      }
    }
  }
}
