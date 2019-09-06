package treasury.crypto

import org.scalatest.prop.TableDrivenPropertyChecks
import org.scalatest.{FunSuite, Matchers}
import treasury.crypto.core.encryption.encryption
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.hash.CryptographicHashFactory
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import treasury.crypto.decryption.{DecryptedRandomnessShareSerializer, RandomnessGenManager}

class RandomnessGenManagerTest extends FunSuite with TableDrivenPropertyChecks with Matchers {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => DiscreteLogGroupFactory.constructDlogGroup(g).get):_*
    )
  val hashes =
    Table(
      "hash",
      AvailableHashes.values.toSeq.map(h => CryptographicHashFactory.constructHash(h).get):_*
    )

  test("randomness generation") {
    forAll(dlogGroups) { implicit group =>
      forAll(hashes) { implicit hash =>
        val (priv, pub) = encryption.createKeyPair.get

        val randomness = RandomnessGenManager.getRand(priv.toByteArray)
        val share = RandomnessGenManager.encryptRandomnessShare(pub, randomness)
        val decryptedShare = RandomnessGenManager.decryptRandomnessShare(priv, share)

        assert(decryptedShare.randomness == randomness)
        assert(RandomnessGenManager.validateDecryptedRandomnessShare(pub, share, decryptedShare))
      }
    }
  }


  test("randomness serialization") {
    forAll(dlogGroups) { implicit group =>
      forAll(hashes) { implicit hash =>
        val (priv, pub) = encryption.createKeyPair.get

        val randomness = RandomnessGenManager.getRand(priv.toByteArray)
        val share = RandomnessGenManager.encryptRandomnessShare(pub, randomness)
        val decryptedShare = RandomnessGenManager.decryptRandomnessShare(priv, share)

        val bytes = decryptedShare.bytes
        val decrypted = DecryptedRandomnessShareSerializer.parseBytes(bytes, Option(group)).get

        assert(decrypted.randomness == randomness)
        assert(RandomnessGenManager.validateDecryptedRandomnessShare(pub, share, decrypted))
      }
    }
  }
}
