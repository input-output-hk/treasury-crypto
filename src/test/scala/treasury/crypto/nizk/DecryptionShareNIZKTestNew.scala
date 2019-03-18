package treasury.crypto.nizk

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.encryption.encryption
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.hash.CryptographicHashFactory
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes

class sDecryptionShareNIZKTestNew extends FunSuite with TableDrivenPropertyChecks {

  implicit val dlogGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  val (privKey, pubKey) = encryption.createKeyPair.get

  val share = dlogGroup.createRandomGroupElement.get
  val decryptedShare = dlogGroup.exponentiate(share, privKey).get

  test("valid nizk") {
    val proof = DecryptionShareNIZKNew.produceNIZK(share, privKey).get
    val verified = DecryptionShareNIZKNew.verifyNIZK(pubKey, share, decryptedShare, proof)

    require(verified)
  }

  test("test wrong decryption") {
    val decryptedShare = dlogGroup.exponentiate(share, dlogGroup.createRandomNumber).get // use wrong key to decrypt

    val proof = DecryptionShareNIZKNew.produceNIZK(share, privKey).get
    val verified = DecryptionShareNIZKNew.verifyNIZK(pubKey, share, decryptedShare, proof)

    require(verified == false)
  }

  test("test invalid share") {
    val proof = DecryptionShareNIZKNew.produceNIZK(share, privKey).get
    val verified = DecryptionShareNIZKNew.verifyNIZK(pubKey, dlogGroup.exponentiate(share, BigInt(4)).get, decryptedShare, proof)

    require(verified == false)
  }
}
