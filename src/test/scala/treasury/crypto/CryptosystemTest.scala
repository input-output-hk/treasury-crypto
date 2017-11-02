package treasury.crypto

import java.math.BigInteger
import java.util

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.util.encoders.Hex
import org.json.JSONObject
import org.scalatest.FunSuite
import treasury.crypto.core.Cryptosystem

import scala.io.Source

class CryptosystemTest extends FunSuite {

  private val jsonTestData = Source.fromResource("cryptosystem_test.json").mkString
  private val jsonObj = new JSONObject(jsonTestData)

  test("encrypt/decrypt message with Lifted ElGamal") {
    val message = BigInteger.valueOf(2).pow(10)

    val cs = new Cryptosystem
    val (privKey, pubKey) = cs.createKeyPair

    val ciphertext = cs.encrypt(pubKey, cs.getRand, message)
    val decryptedMessage = cs.decrypt(privKey, ciphertext)

    assert(message == decryptedMessage)
  }

  test("encryption with Lifted ElGamal") {
    val inputObj = jsonObj.getJSONObject("encryption").getJSONObject("input")
    val cipherObj = jsonObj.getJSONObject("encryption").getJSONObject("output").getJSONObject("ciphertext")

    val pubkey = Hex.decode(inputObj.getString("pubkey"))
    val randomness = new BigInteger(Hex.decode(inputObj.getString("randomness")))
    val message = new BigInteger(Hex.decode(inputObj.getString("message")))

    val cs = new Cryptosystem

    val ciphertextToCheck = (
      cs.decodePoint(Hex.decode(cipherObj.getString("c1"))),
      cs.decodePoint(Hex.decode(cipherObj.getString("c2")))
    )
    val ciphertext = cs.encrypt(cs.decodePoint(pubkey), randomness, message)

    assert(ciphertext._1.equals(ciphertextToCheck._1))
    assert(ciphertext._2.equals(ciphertextToCheck._2))
  }

  test("decryption with Lifted ElGamal") {
    val inputObj = jsonObj.getJSONObject("decryption").getJSONObject("input")
    val cipherObj = inputObj.getJSONObject("ciphertext")
    val outputObj = jsonObj.getJSONObject("decryption").getJSONObject("output")

    val cs = new Cryptosystem

    val privkey = new BigInteger(Hex.decode(inputObj.getString("privkey")))
    val ciphertext = (
      cs.decodePoint(Hex.decode(cipherObj.getString("c1"))),
      cs.decodePoint(Hex.decode(cipherObj.getString("c2")))
    )

    val messageToCheck = new BigInteger(Hex.decode(outputObj.getString("message")))
    val message = cs.decrypt(privkey, ciphertext)

    assert(message.equals(messageToCheck))
  }

  test("classic elgamal encrypt/decrpyt") {
    val cs = new Cryptosystem

    val message = cs.basePoint.multiply(BigInteger.valueOf(1232))

    val (privKey, pubKey) = cs.createKeyPair

    val ciphertext = cs.encryptPoint(pubKey, cs.getRand, message)
    val decryptedMessage = cs.decryptPoint(privKey, ciphertext)

    assert(message.equals(decryptedMessage))
  }

  test("add") {
    val inputObj = jsonObj.getJSONObject("add").getJSONObject("input")
    val cipher1Obj = inputObj.getJSONObject("ciphertext1")
    val cipher2Obj = inputObj.getJSONObject("ciphertext2")
    val cipherOutObj = jsonObj.getJSONObject("add").getJSONObject("output").getJSONObject("ciphertext")

    val cs = new Cryptosystem

    val outToCheck = (cs.decodePoint(Hex.decode(cipherOutObj.getString("c1"))), cs.decodePoint(Hex.decode(cipherOutObj.getString("c2"))))

    val ciphertext1 = (cs.decodePoint(Hex.decode(cipher1Obj.getString("c1"))), cs.decodePoint(Hex.decode(cipher1Obj.getString("c2"))))
    val ciphertext2 = (cs.decodePoint(Hex.decode(cipher2Obj.getString("c1"))), cs.decodePoint(Hex.decode(cipher2Obj.getString("c2"))))


    val out = cs.add(ciphertext1, ciphertext2)

    assert(outToCheck._1.equals(out._1))
    assert(outToCheck._2.equals(out._2))
  }

  test("multiply") {
    val inputObj = jsonObj.getJSONObject("multiply").getJSONObject("input")
    val cipherObj = inputObj.getJSONObject("ciphertext")
    val scalar = inputObj.getString("scalar")
    val outputObj = jsonObj.getJSONObject("multiply").getJSONObject("output").getJSONObject("ciphertext")

    val cs = new Cryptosystem

    val ciphertext = (cs.decodePoint(Hex.decode(cipherObj.getString("c1"))), cs.decodePoint(Hex.decode(cipherObj.getString("c2"))))

    val out = cs.multiply(ciphertext, new BigInteger(Hex.decode(scalar)))
    val outToCheck = (cs.decodePoint(Hex.decode(outputObj.getString("c1"))), cs.decodePoint(Hex.decode(outputObj.getString("c2"))))

    assert(outToCheck._1.equals(out._1))
    assert(outToCheck._2.equals(out._2))
  }

  test("multiply2") {
    val inputObj = jsonObj.getJSONObject("multiply2").getJSONObject("input")
    val cipherObj = inputObj.getJSONObject("ciphertext")
    val scalar = inputObj.getString("scalar")
    val outputObj = jsonObj.getJSONObject("multiply2").getJSONObject("output").getJSONObject("ciphertext")

    val cs = new Cryptosystem

    val ciphertext = (cs.decodePoint(Hex.decode(cipherObj.getString("c1"))), cs.decodePoint(Hex.decode(cipherObj.getString("c2"))))

    val out = cs.multiply(ciphertext, new BigInteger(Hex.decode(scalar)))
    val outToCheck = (cs.decodePoint(Hex.decode(outputObj.getString("c1"))), cs.decodePoint(Hex.decode(outputObj.getString("c2"))))

    assert(outToCheck._1.equals(out._1))
    assert(outToCheck._2.equals(out._2))
  }

  test("hash256") {
    val cs = new Cryptosystem
    val hash = cs.hash256(Array(0))

    assert(hash.length == 32)
  }

  test("using reducible/irreducible element from Zp") {
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")

    val reduced = new BigInteger(Array(10.toByte))
    val notreduced = ecSpec.getN.add(reduced) // add modulo

    val point1 = ecSpec.getG.multiply(reduced).getEncoded(true)
    val point2 = ecSpec.getG.multiply(notreduced).getEncoded(true)

    assert(util.Arrays.equals(point1, point2))
  }

  test("hash to point") {
    val cs = new Cryptosystem
    cs.hashToPoint(Array.fill[Byte](32)(0xFF.toByte))
  }

  test("hybrid_encryption") {

    val cs = new Cryptosystem
    val rnd = new scala.util.Random

    for(i <- 1 to 100)
    {
      val (privKey, pubKey) = cs.createKeyPair

      val message = new Array[Byte](1 + rnd.nextInt(1024)) // message length in range [1, 1024]
      rnd.nextBytes(message)

      val hybridCiphertext = cs.hybridEncrypt(pubKey, message)
      val decryptedMessage = cs.hybridDecrypt(privKey, hybridCiphertext)

      assert(message.sameElements(decryptedMessage))
    }
  }
}
