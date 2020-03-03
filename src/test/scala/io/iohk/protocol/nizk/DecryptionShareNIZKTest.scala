package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

class DecryptionShareNIZKTest extends FunSuite with TableDrivenPropertyChecks {

  implicit val dlogGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  val (privKey, pubKey) = encryption.createKeyPair.get

  val share = dlogGroup.createRandomGroupElement.get
  val decryptedShare = dlogGroup.exponentiate(share, privKey).get

  test("valid nizk") {
    val proof = DecryptionShareNIZK.produceNIZK(share, privKey).get
    val verified = DecryptionShareNIZK.verifyNIZK(pubKey, share, decryptedShare, proof)

    require(verified)
  }

  test("test wrong decryption") {
    val decryptedShare = dlogGroup.exponentiate(share, dlogGroup.createRandomNumber).get // use wrong key to decrypt

    val proof = DecryptionShareNIZK.produceNIZK(share, privKey).get
    val verified = DecryptionShareNIZK.verifyNIZK(pubKey, share, decryptedShare, proof)

    require(verified == false)
  }

  test("test invalid share") {
    val proof = DecryptionShareNIZK.produceNIZK(share, privKey).get
    val verified = DecryptionShareNIZK.verifyNIZK(pubKey, dlogGroup.exponentiate(share, BigInt(4)).get, decryptedShare, proof)

    require(verified == false)
  }
}