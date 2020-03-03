package io.iohk.protocol.nizk

import org.scalameter.picklers.noPickler._
import org.scalameter.{Bench, Gen}
import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.core.crypto.primitives.hash.{CryptographicHash, CryptographicHashFactory}

object DecryptionShareNIZKBench extends Bench.ForkedTime {

  case class TestData(dlogGroup: DiscreteLogGroup, hash: CryptographicHash) {
    val (privKey, pubKey) = encryption.createKeyPair(dlogGroup).get

    val share = dlogGroup.createRandomGroupElement.get
    val decryptedShare = dlogGroup.exponentiate(share, privKey).get
    val proof = DecryptionShareNIZK.produceNIZK(share, privKey)(dlogGroup, hash).get
  }

  val dlogIdsGen = Gen.enumeration("dlog group")(AvailableGroups.values.toSeq:_*)
  val hashIdsGen = Gen.enumeration("hash")(AvailableHashes.values.toSeq:_*)
  val primitivesGen =
    for (group <- dlogIdsGen;
         hash <- hashIdsGen)
    yield TestData(DiscreteLogGroupFactory.constructDlogGroup(group).get, CryptographicHashFactory.constructHash(hash).get)

  performance of "DecryptionShareNIZKNew" in {

    measure method "generateKeyPair" in {
      using(primitivesGen) in { testData: TestData =>
        implicit val dlog = testData.dlogGroup
        implicit val hash = testData.hash
        encryption.createKeyPair
      }
    }

    measure method "create share" in {
      using(primitivesGen) in { testData: TestData =>
        testData.dlogGroup.createRandomGroupElement
      }
    }

    measure method "decrypt share" in {
      using(primitivesGen) in { testData: TestData =>
        testData.dlogGroup.exponentiate(testData.share, testData.privKey)
      }
    }

    measure method "produceNIZK" in {
      using(primitivesGen) in { testData: TestData =>
        implicit val dlog = testData.dlogGroup
        implicit val hash = testData.hash
        DecryptionShareNIZK.produceNIZK(testData.share, testData.privKey)
      }
    }

    measure method "verifyNIZK" in {
      using(primitivesGen) in { testData: TestData =>
        implicit val dlog = testData.dlogGroup
        implicit val hash = testData.hash
        DecryptionShareNIZK.verifyNIZK(testData.pubKey, testData.share, testData.decryptedShare, testData.proof)
      }
    }
  }
}
