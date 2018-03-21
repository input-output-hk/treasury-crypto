package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.Cryptosystem
import treasury.crypto.decryption.{DecryptedRandomnessShareSerializer, RandomnessGenManager}

class RandomnessGenManagerTest extends FunSuite {

  val cs = new Cryptosystem
  val (priv, pub) = cs.createKeyPair

  test("randomness generation") {
    val randomness = RandomnessGenManager.getRand(cs, priv.toByteArray)
    val share = RandomnessGenManager.encryptRandomnessShare(cs, pub, randomness)
    val decryptedShare = RandomnessGenManager.decryptRandomnessShare(cs, priv, share)

    assert(decryptedShare.randomness == randomness)
    assert(RandomnessGenManager.validateDecryptedRandomnessShare(cs, pub, share, decryptedShare))
  }

  test("randomness serialization") {
    val randomness = RandomnessGenManager.getRand(cs, priv.toByteArray)
    val share = RandomnessGenManager.encryptRandomnessShare(cs, pub, randomness)
    val decryptedShare = RandomnessGenManager.decryptRandomnessShare(cs, priv, share)

    val bytes = decryptedShare.bytes
    val decrypted = DecryptedRandomnessShareSerializer.parseBytes(bytes, cs).get

    assert(decrypted.randomness == randomness)
    assert(RandomnessGenManager.validateDecryptedRandomnessShare(cs, pub, share, decrypted))
  }
}
