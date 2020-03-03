package io.iohk.protocol.nizk.unitvectornizk

import java.math.BigInteger

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash

import scala.util.Try

/* UVSumNIZK implements non-interactive zero knowledge proof for a unit vector of ciphertext.
 * Each ciphertext obtained with Lifted Elgamal Encryption Scheme.
 * NIZK proves that the sum of the plaintexts is equal to one. Basically it is equivalent to proving
 * that multiplication of the ciphertexts encrypts one. */

object UVSumNIZK {

  case class UVSumNIZKProof(A1: GroupElement, A2: GroupElement, z: BigInt)

  def produceNIZK(pubKey: PubKey, ciphertexts: Seq[(ElGamalCiphertext, Randomness)])
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[UVSumNIZKProof] = Try {

    val init = ElGamalCiphertext(dlogGroup.groupIdentity, dlogGroup.groupIdentity)
    val C = ciphertexts.foldLeft(init) {
      (acc, c) => acc * c._1
    }
    val R = ciphertexts.foldLeft(BigInt(0)) {
      (acc, c) => acc + c._2
    }.mod(dlogGroup.groupOrder)

    val w = dlogGroup.createRandomNumber
    val A1 = dlogGroup.groupGenerator.pow(w).get
    val A2 = pubKey.pow(w).get

    val e = new BigInteger(
      hashFunction.hash {
        pubKey.bytes ++
        C.bytes ++
        A1.bytes ++
        A2.bytes
      }).mod(dlogGroup.groupOrder)

    val z = (R * e + w) mod dlogGroup.groupOrder

    UVSumNIZKProof(A1, A2, z)
  }

  def verifyNIZK(pubKey: PubKey, ciphertexts: Seq[ElGamalCiphertext], proof: UVSumNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {

    val init = ElGamalCiphertext(dlogGroup.groupIdentity, dlogGroup.groupIdentity)
    val C = ciphertexts.foldLeft(init) {
      (acc, c) => acc * c
    }

    val e = new BigInteger(
      hashFunction.hash {
        pubKey.bytes ++
          C.bytes ++
          proof.A1.bytes ++
          proof.A2.bytes
      }).mod(dlogGroup.groupOrder)

    val C1eA1 = (C.c1.pow(e).get * proof.A1).get
    val gz = dlogGroup.groupGenerator.pow(proof.z).get
    val check1 = C1eA1.equals(gz)

    val C2ge = ((C.c2 / dlogGroup.groupGenerator).get.pow(e).get * proof.A2).get
    val hz = pubKey.pow(proof.z).get
    val check2 = C2ge.equals(hz)

    check1 && check2
  }.getOrElse(false)
}
