package treasury.crypto.nizk

import org.scalameter.{Bench, Gen}
import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.encryption.encryption
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.hash.CryptographicHashFactory
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import treasury.crypto.nizk.DecryptionShareNIZKBench.using

object DecryptionShareNIZKNewBench extends Bench.ForkedTime {

  implicit val dlogGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  val (privKey, pubKey) = encryption.createKeyPair.get

  val share = dlogGroup.createRandomGroupElement.get
  val decryptedShare = dlogGroup.exponentiate(share, privKey).get
  val proof = DecryptionShareNIZKNew.produceNIZK(share, privKey).get

  val gen = Gen.unit("")

  performance of "DecryptionShareNIZKNew" in {

    measure method "generateKeyPair" in {
      using(gen) in { _ =>
        encryption.createKeyPair
      }
    }

    measure method "create share" in {
      using(gen) in { _ =>
        dlogGroup.createRandomGroupElement
      }
    }

    measure method "decrypt share" in {
      using(gen) in { _ =>
        dlogGroup.exponentiate(share, privKey)
      }
    }

    measure method "produceNIZK" in {
      using(gen) in { _ =>
        DecryptionShareNIZKNew.produceNIZK(share, privKey)
      }
    }

    measure method "verifyNIZK" in {
      using(gen) in { _ =>
        DecryptionShareNIZKNew.verifyNIZK(pubKey, share, decryptedShare, proof)
      }
    }
  }
}
