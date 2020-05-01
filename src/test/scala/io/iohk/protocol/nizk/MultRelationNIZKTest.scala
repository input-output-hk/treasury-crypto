package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.Randomness
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.nizk.unitvectornizk.{MultRelationNIZK, MultRelationNIZKProofSerializer}
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

class MultRelationNIZKTest extends FunSuite with TableDrivenPropertyChecks {

  implicit val dlogGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val (privKey, pubKey) = encryption.createKeyPair.get

  private val value = BigInt(111)
  private val encryptedValue = LiftedElGamalEnc.encrypt(pubKey, value).get._1

  private def encryptUnitVector(uv: Array[Int]): Seq[(ElGamalCiphertext, Randomness)] = {
    uv.map { x =>
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, x).get, r)
    }
  }

  private def doValueTest(value: BigInt): Unit = {
    val unitVector = Array(0, 0, 1)
    val encryptedValue_ = LiftedElGamalEnc.encrypt(pubKey, value).get

    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(pubKey, encryptedValue_._1, unitVector)

    val decrypted0 = LiftedElGamalEnc.decrypt(privKey, encryptedUnitVectorWithValue(0)._1).get
    val decrypted1 = LiftedElGamalEnc.decrypt(privKey, encryptedUnitVectorWithValue(1)._1).get
    val decrypted2 = LiftedElGamalEnc.decrypt(privKey, encryptedUnitVectorWithValue(2)._1).get

    assert(decrypted0 == 0)
    assert(decrypted1 == 0)
    assert(decrypted2 == value)
  }

  test("test for valid encrypted unit vector with value") {
    doValueTest(value)
  }

  test("test zero value") {
    doValueTest(0)
  }

  test("test neutral value") {
    doValueTest(0)
  }

  test("test for valid proof") {
    val unitVector = Array(0, 0, 1)

    val encryptedUnitVector = encryptUnitVector(unitVector)
    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(pubKey, encryptedValue, unitVector)

    val proof = MultRelationNIZK.produceNIZK(pubKey, encryptedValue,
      unitVector,
      encryptedUnitVector.map(_._2),
      encryptedUnitVectorWithValue.map(_._2)).get

    val res = MultRelationNIZK.verifyNIZK(pubKey, encryptedValue,
      encryptedUnitVector.map(_._1),
      encryptedUnitVectorWithValue.map(_._1),
      proof)
    assert(res)
  }

  test("test invalid proof") {
    val unitVector = Array(0, 0, 1)

    val encryptedUnitVector = encryptUnitVector(unitVector)
    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(pubKey, encryptedValue, unitVector)

    val proof = MultRelationNIZK.produceNIZK(pubKey, encryptedValue,
      unitVector,
      encryptedUnitVector.map(_._2),
      encryptedUnitVectorWithValue.map(_._2)).get


    assert {
      !MultRelationNIZK.verifyNIZK(pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(X = proof.X.pow(2).get))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(Z = proof.X.pow(2).get))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(x = proof.x + 1))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(y = 0))
    }

    assert {
      !MultRelationNIZK.verifyNIZK(pubKey, encryptedValue,
        encryptedUnitVector.map(_._1),
        encryptedUnitVectorWithValue.map(_._1),
        proof.copy(z = 1))
    }
  }

  test("serialization") {
    val unitVector = Array(0, 0, 1)

    val encryptedUnitVector = encryptUnitVector(unitVector)
    val encryptedUnitVectorWithValue = MultRelationNIZK.produceEncryptedUnitVectorWithValue(pubKey, encryptedValue, unitVector)

    val proof = MultRelationNIZK.produceNIZK(pubKey, encryptedValue,
      unitVector,
      encryptedUnitVector.map(_._2),
      encryptedUnitVectorWithValue.map(_._2)).get

    val bytes = MultRelationNIZKProofSerializer.toBytes(proof)
    val proofFromBytes = MultRelationNIZKProofSerializer.parseBytes(bytes, Option(dlogGroup)).get

    val res = MultRelationNIZK.verifyNIZK(pubKey, encryptedValue,
      encryptedUnitVector.map(_._1),
      encryptedUnitVectorWithValue.map(_._1),
      proofFromBytes)
    assert(res)
  }
}
