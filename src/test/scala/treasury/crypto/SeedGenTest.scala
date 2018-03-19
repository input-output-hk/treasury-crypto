package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.Cryptosystem
import treasury.crypto.decryption.{DecryptedSeedShareSerializer, SeedGenManager}

class SeedGenTest extends FunSuite {

  val cs = new Cryptosystem
  val (priv, pub) = cs.createKeyPair

  test("seed generation") {
    val seed = SeedGenManager.getRand(cs, priv.toByteArray)
    val share = SeedGenManager.encryptSeedShare(cs, pub, seed)
    val decryptedShare = SeedGenManager.decryptSeedShare(cs, priv, share)

    assert(decryptedShare.seed == seed)
    assert(SeedGenManager.validateDecryptedSeedShare(cs, pub, share, decryptedShare))
  }

  test("seed serialization") {
    val seed = SeedGenManager.getRand(cs, priv.toByteArray)
    val share = SeedGenManager.encryptSeedShare(cs, pub, seed)
    val decryptedShare = SeedGenManager.decryptSeedShare(cs, priv, share)

    val bytes = decryptedShare.bytes
    val decrypted = DecryptedSeedShareSerializer.parseBytes(bytes, cs).get

    assert(decrypted.seed == seed)
    assert(SeedGenManager.validateDecryptedSeedShare(cs, pub, share, decrypted))
  }
}
