package treasury.crypto.core.encryption

import org.scalatest.prop.TableDrivenPropertyChecks
import org.scalatest.{FunSuite, Matchers}
import treasury.crypto.core.dlog.DiscreteLogGroupTest
import treasury.crypto.core.encryption.encryption.createKeyPair
import treasury.crypto.core.encryption.elgamal.{ElGamalEnc, LiftedElGamalEnc}
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups

class ElGamalEncTest extends FunSuite with TableDrivenPropertyChecks with Matchers {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => DiscreteLogGroupFactory.constructDlogGroup(g).get):_*
    )

  test("ElGamalEnc should correctly encrypt and decrypt messages") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = createKeyPair.get
      val message = group.createRandomGroupElement.get

      val (ciphertext, randomness) = ElGamalEnc.encrypt(pubKey, message).get
      val decryptedMsg = ElGamalEnc.decrypt(privKey, ciphertext).get

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

      forAll(messages) { msg =>
        val ciphertext = LiftedElGamalEnc.encrypt(pubKey, msg).get._1
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
