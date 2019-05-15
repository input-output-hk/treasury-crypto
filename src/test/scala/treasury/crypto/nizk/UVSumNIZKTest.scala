package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto.core.encryption.elgamal.LiftedElGamalEnc
import treasury.crypto.core.encryption.encryption
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.hash.CryptographicHashFactory
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import treasury.crypto.nizk.unitvectornizk.UVSumNIZK

class UVSumNIZKTest extends FunSuite {

  implicit val dlogGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val (privKey, pubKey) = encryption.createKeyPair.get

  def doTest(unitVector: Array[BigInt]): Boolean = {
    val ciphertexts = unitVector.map { x =>
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, x).get, r)
    }

    val proof = UVSumNIZK.produceNIZK(pubKey, ciphertexts).get
    UVSumNIZK.verifyNIZK(pubKey, ciphertexts.map(_._1), proof)
  }

  test("test for valid unitvector") {
    val unitVector = Array[BigInt](0, 0, 1)
    val verified = doTest(unitVector)

    assert(verified)
  }

  test("test for valid sum") {
    val unitVector = Array[BigInt](-1, 0, 1, 1)
    val verified = doTest(unitVector)

    assert(verified)
  }

  test("test for unit vector of all zeros") {
    val unitVector = Array[BigInt](0, 0, 0)
    val verified = doTest(unitVector)

    assert(verified == false)
  }

  test("test for unit vector with incorrect sum") {
    val unitVector = Array[BigInt](0, 1, 1)
    val verified = doTest(unitVector)

    assert(verified == false)
  }

  test("test for unit vector with negative sum") {
    val unitVector = Array[BigInt](0, -1, 0)
    val verified = doTest(unitVector)

    assert(verified == false)
  }
}
