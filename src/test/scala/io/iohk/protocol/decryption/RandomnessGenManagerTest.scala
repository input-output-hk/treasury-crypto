package io.iohk.protocol.decryption

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import org.scalatest.prop.TableDrivenPropertyChecks
import org.scalatest.{FunSuite, Matchers}

class RandomnessGenManagerTest extends FunSuite with TableDrivenPropertyChecks with Matchers {

  val ctx = new CryptoContext
  import ctx.group

  test("randomness generation") {
    val (priv, pub) = encryption.createKeyPair.get

    val randomness = RandomnessGenManager.getRand(ctx, priv.toByteArray)
    val share = RandomnessGenManager.encryptRandomnessShare(ctx, pub, randomness)
    val decryptedShare = RandomnessGenManager.decryptRandomnessShare(ctx, priv, share)

    assert(decryptedShare.randomness == randomness)
    assert(RandomnessGenManager.validateDecryptedRandomnessShare(ctx, pub, share, decryptedShare))
  }


  test("randomness serialization") {
    val (priv, pub) = encryption.createKeyPair.get

    val randomness = RandomnessGenManager.getRand(ctx, priv.toByteArray)
    val share = RandomnessGenManager.encryptRandomnessShare(ctx, pub, randomness)
    val decryptedShare = RandomnessGenManager.decryptRandomnessShare(ctx, priv, share)

    val bytes = decryptedShare.bytes
    val decrypted = DecryptedRandomnessShareSerializer.parseBytes(bytes, Option(group)).get

    assert(decrypted.randomness == randomness)
    assert(RandomnessGenManager.validateDecryptedRandomnessShare(ctx, pub, share, decrypted))
  }
}
