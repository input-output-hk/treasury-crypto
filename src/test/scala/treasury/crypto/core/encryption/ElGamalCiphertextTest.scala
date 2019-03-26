package treasury.crypto.core.encryption

import org.scalatest.prop.TableDrivenPropertyChecks
import org.scalatest.{FunSuite, Matchers}
import treasury.crypto.core.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer, ElGamalEnc}
import treasury.crypto.core.encryption.encryption.createKeyPair
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups

class ElGamalCiphertextTest extends FunSuite with TableDrivenPropertyChecks with Matchers {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => DiscreteLogGroupFactory.constructDlogGroup(g).get):_*
    )

  test("ElGamalCiphertext interface should support pow operation") {
    forAll(dlogGroups) { implicit group =>
      val e1 = group.createRandomGroupElement.get
      val e2 = e1

      val c = ElGamalCiphertext(e1, e2)
      val pow = c.pow(5).get

      pow.c1 should be (pow.c2)
      pow.c1 should not be (e1)
    }
  }

  test("ElGamalCiphertext interface should support multiply operation") {
    forAll(dlogGroups) { implicit group =>
      val e1 = group.createRandomGroupElement.get
      val e2 = e1

      val c = ElGamalCiphertext(e1, e2)
      val iden = ElGamalCiphertext(group.groupIdentity, group.groupIdentity)
      val res = c.multiply(iden).get
      val res2 = c * iden

      res.c1 should be (res.c2)
      res.c1 should be (e1)
      res2.c1 should be (res2.c2)
      res2.c1 should be (e1)

      val c2 = ElGamalCiphertext(group.groupGenerator, group.groupGenerator)
      val res3 = c.multiply(c2).get
      val res4 = c * c2

      res3.c1 should be (res3.c2)
      res3.c1 should not be (e1)
      res4.c1 should be (res4.c2)
      res4.c1 should not be (e1)
    }
  }

  test("ElGamalCiphertext should support serialization") {
    forAll(dlogGroups) { implicit group =>
      val (privKey, pubKey) = createKeyPair.get
      val message = group.createRandomGroupElement.get

      val (ciphertext, _) = ElGamalEnc.encrypt(pubKey, message).get
      val bytes = ciphertext.bytes
      val reconstructedCiphertext = ElGamalCiphertextSerializer.parseBytes(bytes, Option(group)).get
      val decryptedMsg = ElGamalEnc.decrypt(privKey, reconstructedCiphertext).get

      decryptedMsg should be (message)
    }
  }
}
