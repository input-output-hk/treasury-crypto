package treasury.crypto.nizk.unitvectornizk

import java.math.BigInteger

import treasury.crypto.core._

/* UVSumNIZK implements non-interactive zero knowledge proof for a unit vector of ciphertext.
 * Each ciphertext obtained with Lifted Elgamal Encryption Scheme.
 * NIZK proves that the sum of the plaintexts is equal to one. Basically it is equivalent to proving
 * that multiplication of the ciphertexts encrypts one. */

object UVSumNIZK {

  case class UVSumNIZKProof(A1: Point, A2: Point, z: Element)

  def produceNIZK(cs: Cryptosystem,
                  pubKey: PubKey,
                  ciphertexts: Seq[(Ciphertext, Randomness)]): UVSumNIZKProof = {

    val C = ciphertexts.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
      (acc, c) => (acc._1.add(c._1._1), acc._2.add(c._1._2))
    }
    val R = ciphertexts.foldLeft(Zero) {
      (acc, c) => acc.add(c._2)
    }.mod(cs.orderOfBasePoint)

    val w = cs.getRand
    val A1 = cs.basePoint.multiply(w)
    val A2 = pubKey.multiply(w)

    val e = new BigInteger(
      cs.hash256 {
        pubKey.getEncoded(true) ++
        C._1.getEncoded(true) ++
        C._2.getEncoded(true) ++
        A1.getEncoded(true) ++
        A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val z = R.multiply(e).add(w)

    UVSumNIZKProof(A1, A2, z)
  }

  def verifyNIZK(cs: Cryptosystem,
                 pubKey: PubKey,
                 ciphertexts: Seq[(Ciphertext)],
                 proof: UVSumNIZKProof): Boolean = {
    val C = ciphertexts.foldLeft((cs.infinityPoint, cs.infinityPoint)) {
      (acc, c) => (acc._1.add(c._1), acc._2.add(c._2))
    }

    val e = new BigInteger(
      cs.hash256 {
        pubKey.getEncoded(true) ++
          C._1.getEncoded(true) ++
          C._2.getEncoded(true) ++
          proof.A1.getEncoded(true) ++
          proof.A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val C1eA1 = C._1.multiply(e).add(proof.A1)
    val gz = cs.basePoint.multiply(proof.z)
    val check1 = C1eA1.equals(gz)

    val C2ge = C._2.subtract(cs.basePoint).multiply(e).add(proof.A2)
    val hz = pubKey.multiply(proof.z)
    val check2 = C2ge.equals(hz)

    check1 && check2
  }
}
