package treasury.crypto.nizk

import org.scalameter.picklers.noPickler._
import org.scalameter.{Bench, Gen}
import treasury.crypto.core.encryption.encryption
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import treasury.crypto.core.primitives.hash.{CryptographicHash, CryptographicHashFactory}
import treasury.crypto.nizk.shvzk_new.SHVZKVerifier
import treasury.crypto.nizk.shvzk_new.SHVZKGen

object SHVZKBench extends Bench.ForkedTime {

  val shvzkTest = new SHVZKTestNew()

  case class TestData(dlogGroup: DiscreteLogGroup, hash: CryptographicHash, vectorSize: Int) {
    val (privKey, pubKey) = encryption.createKeyPair(dlogGroup).get

    val (uv, rand) = shvzkTest.createUnitVector(vectorSize, 3, pubKey)(dlogGroup)
    val proof = new SHVZKGen(pubKey, uv, 3, rand)(dlogGroup, hash).produceNIZK.get
  }

  val dlogIdsGen = Gen.enumeration("dlog group")(AvailableGroups.values.toSeq:_*)
  val hashIdsGen = Gen.enumeration("hash")(AvailableHashes.values.toSeq:_*)
  val vectorSizeGen = Gen.enumeration("vector size")(/*7, 15, 16, 31, 63,*/ 127/*, 128, 255*/)
  val testDataGen =
    for (group <- dlogIdsGen;
         hash <- hashIdsGen;
         vecSize <- vectorSizeGen)
      yield TestData(DiscreteLogGroupFactory.constructDlogGroup(group).get, CryptographicHashFactory.constructHash(hash).get, vecSize)

  performance of "SHVZKNIZKNew" in {

    measure method "createUnitVector" in {
      using(testDataGen) in { testData: TestData =>
        implicit val dlog = testData.dlogGroup
        shvzkTest.createUnitVector(testData.vectorSize, 3, testData.pubKey)
      }
    }

    measure method "produceNIZK" in {
      using(testDataGen) in { testData: TestData =>
        implicit val dlog = testData.dlogGroup
        implicit val hash = testData.hash
        new SHVZKGen(testData.pubKey, testData.uv, 3, testData.rand).produceNIZK.get
      }
    }

    measure method "verifyNIZK" in {
      using(testDataGen) in { testData: TestData =>
        implicit val dlog = testData.dlogGroup
        implicit val hash = testData.hash
        new SHVZKVerifier(testData.pubKey, testData.uv, testData.proof).verifyProof
      }
    }
  }
}
