package treasury.crypto.core.encryption

import org.scalatest.prop.TableDrivenPropertyChecks
import org.scalatest.{FunSuite, Matchers}
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups

class ElGamalEncTest extends FunSuite with TableDrivenPropertyChecks with Matchers {

  val dlogGroups =
    Table(
      "group",
      DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
    )

  test("ElGamalEnc should correctly encrypt and decrypt messages") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = createKeyPair.get
      val message = group.createRandomGroupElement.get
      val rand = group.createRandomNumber

      val ciphertext = ElGamalEnc.encrypt(group, pubKey, rand, message).get
      val decryptedMsg = ElGamalEnc.decrypt(group, privKey, ciphertext).get

      ciphertext should not be (decryptedMsg)
      decryptedMsg should be (message)
    }
  }
}
