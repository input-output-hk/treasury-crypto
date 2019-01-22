package treasury.crypto.nizk

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.core
import treasury.crypto.core._
import treasury.crypto.nizk.unitvectornizk.{MultRelationNIZK, MultRelationNIZKProofSerializer}

class MultRelationNIZKTest extends FunSuite {
  private val cs = new Cryptosystem
  private val (privKey, pubKey) = cs.createKeyPair

  private val value = BigInteger.valueOf(111)
  private val encryptedValue = cs.encrypt(pubKey, cs.getRand, value)

  private def encryptUnitVector(uv: Array[BigInteger]): Seq[(Ciphertext, Randomness)] = {
    uv.map { x =>
      val r = cs.getRand
      (cs.encrypt(pubKey, r, x), r)
    }
  }

  private def doValueTest(value: BigInteger): Unit = {
    val unitVector = Array[BigInteger](Zero, Zero, One)
    val encryptedValue_ = cs.encrypt(pubKey, cs.getRand, value)

    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(cs, pubKey, encryptedValue_, unitVector)

    val decrypted0 = cs.decrypt(privKey, encryptedUnitVectorWithValue(0)._1)
    val decrypted1 = cs.decrypt(privKey, encryptedUnitVectorWithValue(1)._1)
    val decrypted2 = cs.decrypt(privKey, encryptedUnitVectorWithValue(2)._1)

    assert(decrypted0.equals(core.Zero))
    assert(decrypted1.equals(core.Zero))
    assert(decrypted2.equals(value))
  }

  test("test for valid encrypted unit vector with value") {
    doValueTest(value)
  }

  test("test zero value") {
    doValueTest(core.Zero)
  }

  test("test neutral value") {
    doValueTest(core.One)
  }

  test("test for valid proof") {
    val unitVector = Array[BigInteger](Zero, Zero, One)

    val encryptedUnitVector = encryptUnitVector(unitVector)
    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(cs, pubKey, encryptedValue, unitVector)

    val proof = MultRelationNIZK.produceNIZK(cs, pubKey, encryptedValue,
      unitVector,
      encryptedUnitVector.map(_._2),
      encryptedUnitVectorWithValue.map(_._2))

    val res = MultRelationNIZK.verifyNIZK(cs, pubKey, encryptedValue,
      encryptedUnitVector.map(_._1),
      encryptedUnitVectorWithValue.map(_._1),
      proof)
    assert(res)
  }

  test("test invalid proof") {
    val unitVector = Array[BigInteger](Zero, Zero, One)

    val encryptedUnitVector = encryptUnitVector(unitVector)
    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(cs, pubKey, encryptedValue, unitVector)

    val proof = MultRelationNIZK.produceNIZK(cs, pubKey, encryptedValue,
      unitVector,
      encryptedUnitVector.map(_._2),
      encryptedUnitVectorWithValue.map(_._2))


    assert {
      !MultRelationNIZK.verifyNIZK(cs, pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(X = cs.multiply(proof.X, BigInteger.valueOf(2))))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(cs, pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(Z = cs.multiply(proof.X, BigInteger.valueOf(2))))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(cs, pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(x = proof.x.add(core.One)))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(cs, pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(y = core.Zero))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(cs, pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(z = core.One))
    }
  }

  test("serialization") {
    val unitVector = Array[BigInteger](Zero, Zero, One)

    val encryptedUnitVector = encryptUnitVector(unitVector)
    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(cs, pubKey, encryptedValue, unitVector)

    val proof = MultRelationNIZK.produceNIZK(cs, pubKey, encryptedValue,
      unitVector,
      encryptedUnitVector.map(_._2),
      encryptedUnitVectorWithValue.map(_._2))

    val bytes = MultRelationNIZKProofSerializer.toBytes(proof)
    val proofFromBytes = MultRelationNIZKProofSerializer.parseBytes(bytes, cs).get

    val res = MultRelationNIZK.verifyNIZK(cs, pubKey, encryptedValue,
      encryptedUnitVector.map(_._1),
      encryptedUnitVectorWithValue.map(_._1),
      proofFromBytes)
    assert(res)
  }
}
