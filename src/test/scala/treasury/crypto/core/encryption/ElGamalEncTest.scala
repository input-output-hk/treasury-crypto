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

      decryptedMsg should be (message)
    }
  }

  val messages =
    Table(
      "message",
      BigInt(0), BigInt(1), BigInt(2), BigInt(100), BigInt(23534), BigInt(LiftedElGamalEnc.MSG_RANGE-1)
    )

  test("LiftedElGamalEnc should correctly encrypt and decrypt messages") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = createKeyPair.get
      val rand = group.createRandomNumber

      forAll(messages) { msg =>
        val ciphertext = LiftedElGamalEnc.encrypt(pubKey, rand, msg).get
        val decryptedMsg = LiftedElGamalEnc.decrypt(privKey, ciphertext).get

        decryptedMsg should be (msg)
      }
    }
  }

  test("LiftedElGamalEnc should fail to decrypt if a message is not from allowed range") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = createKeyPair.get
      val rand = group.createRandomNumber

      val ciphertext = LiftedElGamalEnc.encrypt(pubKey, rand, LiftedElGamalEnc.MSG_RANGE).get
      val decryptedMsg = LiftedElGamalEnc.decrypt(privKey, ciphertext)

      decryptedMsg.isFailure should be (true)
    }
  }
}
