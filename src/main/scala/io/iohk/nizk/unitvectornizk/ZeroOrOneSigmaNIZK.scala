package io.iohk.nizk.unitvectornizk

import io.iohk.core.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.encryption.{PubKey, Randomness}
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.primitives.hash.CryptographicHash
import io.iohk.core.primitives.numbergenerator.SP800DRNG

import scala.util.Try


/* This class implements well-known Chaum-Pedersen protocol to prove that a ciphertext encrypts
 * zero or one (via Sigma OR composition). Ciphertext is obtained with Lifted Elgamal encryption scheme. */

object ZeroOrOneSigmaNIZK {

  case class ZeroOrOneSigmaNIZKProof(A1: GroupElement, A2: GroupElement, B1: GroupElement, B2: GroupElement, e2: Array[Byte], z1: BigInt, z2: BigInt)

  def produceNIZK(pubKey: PubKey, plaintext: BigInt, ciphertext: ElGamalCiphertext, r: Randomness)
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[ZeroOrOneSigmaNIZKProof] = Try {

    if (plaintext == 0) {
      val w = dlogGroup.createRandomNumber
      val z2 = dlogGroup.createRandomNumber

      val e2 = new SP800DRNG(dlogGroup.createRandomNumber.toByteArray).nextBytes(32) // normally we should use here some pure RNG instead of dlogGroup
      val E2 = BigInt(e2).mod(dlogGroup.groupOrder)

      val A1 = dlogGroup.groupGenerator.pow(w).get
      val A2 = pubKey.pow(w).get

      val B1 = (dlogGroup.groupGenerator.pow(z2).get / ciphertext.c1.pow(E2).get).get
      val B2 = pubKey.pow(z2).get.divide {
        (ciphertext.c2 / dlogGroup.groupGenerator).get.pow(E2).get
      }.get

      val e = hashFunction.hash {
        pubKey.bytes ++
        ciphertext.bytes ++
        A1.bytes ++
        A2.bytes ++
        B1.bytes ++
        B2.bytes
      }
      val zip = e.zip(e2)
      val e1 = zip.map(x => (x._1 ^ x._2).toByte)  // e1 = e XOR e2
      val z1 = ((r * BigInt(e1)) + w) mod(dlogGroup.groupOrder)

      ZeroOrOneSigmaNIZKProof(A1, A2, B1, B2, e2, z1, z2)
    } else  {
      val z1 = dlogGroup.createRandomNumber
      val v = dlogGroup.createRandomNumber
      val e1 = new SP800DRNG(dlogGroup.createRandomNumber.toByteArray).nextBytes(32) // normally we should use here some pure RNG instead of dlogGroup
      val E1 = BigInt(e1).mod(dlogGroup.groupOrder)

      val B1 = dlogGroup.groupGenerator.pow(v).get
      val B2 = pubKey.pow(v).get

      val A1 = (dlogGroup.groupGenerator.pow(z1).get / ciphertext.c1.pow(E1).get).get
      val A2 = (pubKey.pow(z1).get / ciphertext.c2.pow(E1).get).get

      val e = hashFunction.hash {
        pubKey.bytes ++
        ciphertext.bytes ++
        A1.bytes ++
        A2.bytes ++
        B1.bytes ++
        B2.bytes
      }

      val zip = e.zip(e1)
      val e2 = zip.map(x => (x._1 ^ x._2).toByte)  // e2 = e XOR e1
      val z2 = (r * BigInt(e2) + v) mod(dlogGroup.groupOrder)

      ZeroOrOneSigmaNIZKProof(A1, A2, B1, B2, e2, z1, z2)
    }
  }

  def verifyNIZK(pubKey: PubKey, ciphertext: ElGamalCiphertext, proof: ZeroOrOneSigmaNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {
    val e = hashFunction.hash {
      pubKey.bytes ++
      ciphertext.bytes ++
      proof.A1.bytes ++
      proof.A2.bytes ++
      proof.B1.bytes ++
      proof.B2.bytes
    }
    val zip = e.zip(proof.e2)
    val e1 = BigInt(zip.map(x => (x._1 ^ x._2).toByte)).mod(dlogGroup.groupOrder)  // e1 = e XOR e2

    val c1e1A1 = (ciphertext.c1.pow(e1).get * proof.A1).get
    val gz1 = dlogGroup.groupGenerator.pow(proof.z1).get
    val check1 = c1e1A1.equals(gz1)

    val c2e1A2 = (ciphertext.c2.pow(e1).get * proof.A2).get
    val hz1 = pubKey.pow(proof.z1).get
    val check2 = c2e1A2.equals(hz1)

    val e2 = BigInt(proof.e2)
    val c1e2B1 = (ciphertext.c1.pow(e2).get * proof.B1).get
    val gz2 = dlogGroup.groupGenerator.pow(proof.z2).get
    val check3 = c1e2B1.equals(gz2)

    val c2ge2B2 = ((ciphertext.c2 / dlogGroup.groupGenerator).get.pow(e2).get * proof.B2).get
    val hz2 = pubKey.pow(proof.z2).get
    val check4 = c2ge2B2.equals(hz2)

    check1 && check2 && check3 && check4
  }.getOrElse(false)
}
