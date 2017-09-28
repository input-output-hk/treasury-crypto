import org.scalatest.FunSuite

class EllipticCurveCryptosystemTest extends FunSuite {

  test("encrypt/decrypt message") {
    val message = math.pow(2, 15).toInt
    val rand = Array[Byte](100)

    val cs = new EllipticCurveCryptosystem
    val (privKey, pubKey) = cs.createKeyPair()

    val ciphertext = cs.encrypt(pubKey, rand, message)
    val decryptedMessage = cs.decrypt(privKey, ciphertext)

    assert(message == decryptedMessage)
  }
}
