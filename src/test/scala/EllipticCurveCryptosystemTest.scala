import java.util

import org.bouncycastle.util.encoders.{Base64, Hex}
import org.json.JSONObject
import org.scalatest.FunSuite

import scala.io.Source

class EllipticCurveCryptosystemTest extends FunSuite {

  val jsonTestData = Source.fromResource("cryptosystem_test.json").mkString
  val jsonObj = new JSONObject(jsonTestData);

  test("encrypt/decrypt message") {
    val message = math.pow(2, 10).toInt
    val rand = Array[Byte](100)

    val cs = new EllipticCurveCryptosystem
    val (privKey, pubKey) = cs.createKeyPair()

    val ciphertext = cs.encrypt(pubKey, rand, message)
    val decryptedMessage = cs.decrypt(privKey, ciphertext)

    assert(message == decryptedMessage)
  }

  test("encryption") {
    val inputObj = jsonObj.getJSONObject("encryption").getJSONObject("input")
    val cipherObj = jsonObj.getJSONObject("encryption").getJSONObject("output").getJSONObject("ciphertext")

    val pubkey = Hex.decode(inputObj.getString("pubkey"))
    val randomness = Hex.decode(inputObj.getString("randomness"))
    val message = Integer.parseInt(inputObj.getString("message"), 16)

    val ciphertextToCheck = (Hex.decode(cipherObj.getString("c1")), Hex.decode(cipherObj.getString("c2")))

    val cs = new EllipticCurveCryptosystem
    val ciphertext = cs.encrypt(pubkey, randomness, message)

    assert(util.Arrays.equals(ciphertext._1, ciphertextToCheck._1))
  }

  test("decryption") {
    val inputObj = jsonObj.getJSONObject("decryption").getJSONObject("input")
    val cipherObj = inputObj.getJSONObject("ciphertext")
    val outputObj = jsonObj.getJSONObject("decryption").getJSONObject("output")

    val privkey = Hex.decode(inputObj.getString("privkey"))
    val ciphertext = (Hex.decode(cipherObj.getString("c1")), Hex.decode(cipherObj.getString("c2")))

    val messageToCheck = Integer.parseInt(outputObj.getString("message"), 16)

    val cs = new EllipticCurveCryptosystem
    val message = cs.decrypt(privkey, ciphertext)

    assert(message == messageToCheck)
  }
}
