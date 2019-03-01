package treasury.crypto.nizk

import org.scalameter.{Bench, Gen}
import treasury.crypto.core.Cryptosystem

object DecryptionShareNIZKBench extends Bench.ForkedTime {

  val cs = new Cryptosystem

  val (privKey, pubKey) = cs.createKeyPair
  val share = cs.basePoint.multiply(cs.getRand)
  val decryptedShare = share.multiply(privKey)
  val proof = DecryptionShareNIZK.produceNIZK(cs, share, privKey)

  val gen = Gen.unit("")

  performance of "DecryptionShareNIZK" in {

    measure method "generateKeyPair" in {
      using(gen) in { _ =>
        cs.createKeyPair
      }
    }

    measure method "create share" in {
      using(gen) in { _ =>
        cs.basePoint.multiply(privKey)
      }
    }

    measure method "decrypt share" in {
      using(gen) in { _ =>
        share.multiply(privKey)
      }
    }

    measure method "produceNIZK" in {
      using(gen) in { _ =>
        DecryptionShareNIZK.produceNIZK(cs, share, privKey)
      }
    }

    measure method "verifyNIZK" in {
      using(gen) in { _ =>
        DecryptionShareNIZK.verifyNIZK(cs, pubKey, share, decryptedShare, proof)
      }
    }
  }
}
