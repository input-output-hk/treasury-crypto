package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.nizk.unitvectornizk.{AllOneNIZK, AllOneNIZKProofSerializer}
import org.scalatest.FunSuite

class AllOneNIZKTest extends FunSuite {

  implicit val dlogGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
  implicit val hashFunction = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val (privKey, pubKey) = encryption.createKeyPair.get

  test("valid vector of 1") {
    val ciphertexts = (0 until 10).map { _ =>
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 1).get, r)
    }

    val proof = AllOneNIZK.produceNIZK(pubKey, ciphertexts).get
    val verified = AllOneNIZK.verifyNIZK(pubKey, ciphertexts.map(_._1), proof)
    require(verified)

    val proof2 = AllOneNIZK.produceNIZK(pubKey, ciphertexts.take(1)).get
    require(AllOneNIZK.verifyNIZK(pubKey, ciphertexts.take(1).map(_._1), proof2))

    val proof3 = AllOneNIZK.produceNIZK(pubKey, Seq()).get
    require(AllOneNIZK.verifyNIZK(pubKey, Seq(), proof3))
  }

  test("invalid vector with zeros") {
    val ciphertexts = (0 until 10).map { _ =>
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 0).get, r)
    }
    val proof = AllOneNIZK.produceNIZK(pubKey, ciphertexts).get
    val verified = AllOneNIZK.verifyNIZK(pubKey, ciphertexts.map(_._1), proof)
    require(verified == false)


    val zero = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 0).get, r)
    }
    val ciphertexts2 = (0 until 10).map { _ =>
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 1).get, r)
    } :+ zero
    val proof2 = AllOneNIZK.produceNIZK(pubKey, ciphertexts2).get
    require(!AllOneNIZK.verifyNIZK(pubKey, ciphertexts2.map(_._1), proof2))
  }

  test("invalid vector with different numbers") {
    val ciphertexts = (0 until 10).map { i =>
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, i).get, r)
    }
    val proof = AllOneNIZK.produceNIZK(pubKey, ciphertexts).get
    val verified = AllOneNIZK.verifyNIZK(pubKey, ciphertexts.map(_._1), proof)
    require(verified == false)


    val two = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 2).get, r)
    }
    val zero = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 0).get, r)
    }
    val v = Seq(two, zero)
    val proof2 = AllOneNIZK.produceNIZK(pubKey, v).get
    require(!AllOneNIZK.verifyNIZK(pubKey, v.map(_._1), proof2))
  }

  test("invalid proof") {
    val one = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 1).get, r)
    }
    val zero = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 0).get, r)
    }

    val proof = AllOneNIZK.produceNIZK(pubKey, Seq(one)).get
    require(AllOneNIZK.verifyNIZK(pubKey, Seq(one._1), proof))
    require(!AllOneNIZK.verifyNIZK(pubKey, Seq(zero._1), proof))
    require(!AllOneNIZK.verifyNIZK(pubKey, Seq(one._1), proof.copy(T1 = proof.T2)))
  }

  test("serialization") {
    val one = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 1).get, r)
    }
    val proof = AllOneNIZK.produceNIZK(pubKey, Seq(one)).get
    val bytes = proof.bytes
    val restoredProof = AllOneNIZKProofSerializer.parseBytes(bytes, Option(dlogGroup)).get
    require(proof.T1 == restoredProof.T1 && proof.T2 == restoredProof.T2 && proof.z == restoredProof.z)
    require(AllOneNIZK.verifyNIZK(pubKey, Seq(one._1), restoredProof))
  }

  test("summation of vectors") {
    def one = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 1).get, r)
    }
    def zero = {
      val r = dlogGroup.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 0).get, r)
    }

    val v1 = Seq(one, zero)
    val v2 = Seq(zero, one)
    val v3 = Seq(zero, zero)
    val neutralCiphertext = ElGamalCiphertext(dlogGroup.groupIdentity, dlogGroup.groupIdentity)
    val init = Seq((neutralCiphertext, BigInt(0)), (neutralCiphertext, BigInt(0)))

    val sum = Seq(v1,v2,v3).foldLeft(init) { (acc, v) =>
      acc.zip(v).map { case (e1, e2) =>
        (e1._1.multiply(e2._1).get, e1._2 + e2._2)
      }
    }

    val proof = AllOneNIZK.produceNIZK(pubKey, sum).get
    require(AllOneNIZK.verifyNIZK(pubKey, sum.map(_._1), proof))
  }
}
