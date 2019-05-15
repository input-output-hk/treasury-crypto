package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto.core.encryption.elgamal.LiftedElGamalEnc
import treasury.crypto.core.encryption.encryption
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.hash.CryptographicHashFactory
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import treasury.crypto.nizk.unitvectornizk.ZeroOrOneSigmaNIZK

class ZeroOrOneSigmaNIZKTest extends FunSuite {

  implicit val dlogGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val (privKey, pubKey) = encryption.createKeyPair.get

  test("encrypt one") {
    val r = dlogGroup.createRandomNumber
    val c = LiftedElGamalEnc.encrypt(pubKey, r, 1).get

    val proof = ZeroOrOneSigmaNIZK.produceNIZK(pubKey, 1, c, r).get
    val verified = ZeroOrOneSigmaNIZK.verifyNIZK(pubKey, c, proof)

    assert(verified)
  }

  test("encrypt zero") {
    val r = dlogGroup.createRandomNumber
    val c = LiftedElGamalEnc.encrypt(pubKey, r, 0).get

    val proof = ZeroOrOneSigmaNIZK.produceNIZK(pubKey, 0, c, r).get
    val verified = ZeroOrOneSigmaNIZK.verifyNIZK(pubKey, c, proof)

    assert(verified)
  }

  test("encrypt two") {
    val m = BigInt(2)
    val r = dlogGroup.createRandomNumber
    val c = LiftedElGamalEnc.encrypt(pubKey, r, m).get

    val proof = ZeroOrOneSigmaNIZK.produceNIZK(pubKey, m, c, r).get
    val verified = ZeroOrOneSigmaNIZK.verifyNIZK(pubKey, c, proof)

    assert(verified == false)
  }

  test("encrypt -1") {
    val m = BigInt(-1)
    val r = dlogGroup.createRandomNumber
    val c = LiftedElGamalEnc.encrypt(pubKey, r, m).get

    val proof = ZeroOrOneSigmaNIZK.produceNIZK(pubKey, m, c, r).get
    val verified = ZeroOrOneSigmaNIZK.verifyNIZK(pubKey, c, proof)

    assert(verified == false)
  }

  test("inconsistent ciphertext") {
    val r = dlogGroup.createRandomNumber
    val c = LiftedElGamalEnc.encrypt(pubKey, r, 0).get

    val proof = ZeroOrOneSigmaNIZK.produceNIZK(pubKey, 1, c, r).get
    val verified = ZeroOrOneSigmaNIZK.verifyNIZK(pubKey, c, proof)

    assert(verified == false)
  }
}
