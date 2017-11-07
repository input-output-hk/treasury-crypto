package treasury.crypto.nizk.unitvectornizk

import java.math.BigInteger

import treasury.crypto.core._

/* This class implements well-known Chaum-Pedersen protocol to prove that a ciphertext encrypts
 * zero or one (via Sigma OR composition). Ciphertext is obtained with Lifted Elgamal encryption scheme. */

object ZeroOrOneSigmaNIZK {

  case class ZeroOrOneSigmaNIZKProof(A1: Point, A2: Point, B1: Point, B2: Point, e2: Array[Byte], z1: Element, z2: Element)

  def produceNIZK(cs: Cryptosystem,
                  pubKey: PubKey,
                  plaintext: Element,
                  ciphertext: Ciphertext,
                  r: Randomness): ZeroOrOneSigmaNIZKProof = {
    if (plaintext.equals(Zero)) {
      val w = cs.getRand
      val z2 = cs.getRand
      val e2 = cs.getRandBytes(32)
      val E2 = new BigInteger(e2).mod(cs.orderOfBasePoint)

      val A1 = cs.basePoint.multiply(w)
      val A2 = pubKey.multiply(w)

      val B1 = cs.basePoint.multiply(z2).subtract(ciphertext._1.multiply(E2))
      val B2 = pubKey.multiply(z2).subtract {
        ciphertext._2.subtract(cs.basePoint).multiply(E2)
      }

      val e = cs.hash256 {
        pubKey.getEncoded(true) ++
        ciphertext._1.getEncoded(true) ++
        ciphertext._2.getEncoded(true) ++
        A1.getEncoded(true) ++
        A2.getEncoded(true) ++
        B1.getEncoded(true) ++
        B2.getEncoded(true)
      }
      val zip = e.zip(e2)
      val e1 = zip.map(x => (x._1 ^ x._2).toByte)  // e1 = e XOR e2
      val z1 = r.multiply(new BigInteger(e1)).add(w).mod(cs.orderOfBasePoint)

      ZeroOrOneSigmaNIZKProof(A1, A2, B1, B2, e2, z1, z2)
    } else  {
      val z1 = cs.getRand
      val v = cs.getRand
      val e1 = cs.getRandBytes(32)
      val E1 = new BigInteger(e1).mod(cs.orderOfBasePoint)

      val B1 = cs.basePoint.multiply(v).normalize
      val B2 = pubKey.multiply(v).normalize

      val A1 = cs.basePoint.multiply(z1).subtract(ciphertext._1.multiply(E1)).normalize
      val A2 = pubKey.multiply(z1).subtract(ciphertext._2.multiply(E1)).normalize

      val e = cs.hash256 {
        pubKey.getEncoded(true) ++
        ciphertext._1.getEncoded(true) ++
        ciphertext._2.getEncoded(true) ++
        A1.getEncoded(true) ++
        A2.getEncoded(true) ++
        B1.getEncoded(true) ++
        B2.getEncoded(true)
      }

      val zip = e.zip(e1)
      val e2 = zip.map(x => (x._1 ^ x._2).toByte)  // e2 = e XOR e1
      val z2 = r.multiply(new BigInteger(e2)).add(v).mod(cs.orderOfBasePoint)

      ZeroOrOneSigmaNIZKProof(A1, A2, B1, B2, e2, z1, z2)
    }
  }

  def verifyNIZK(cs: Cryptosystem, pubKey: PubKey, ciphertext: Ciphertext, proof: ZeroOrOneSigmaNIZKProof): Boolean = {
    val e = cs.hash256 {
      pubKey.getEncoded(true) ++
      ciphertext._1.getEncoded(true) ++
      ciphertext._2.getEncoded(true) ++
      proof.A1.getEncoded(true) ++
      proof.A2.getEncoded(true) ++
      proof.B1.getEncoded(true) ++
      proof.B2.getEncoded(true)
    }
    val zip = e.zip(proof.e2)
    val e1 = new BigInteger(zip.map(x => (x._1 ^ x._2).toByte)).mod(cs.orderOfBasePoint)  // e1 = e XOR e2

    val c1e1A1 = ciphertext._1.multiply(e1).add(proof.A1)
    val gz1 = cs.basePoint.multiply(proof.z1)
    val check1 = c1e1A1.equals(gz1)

    val c2e1A2 = ciphertext._2.multiply(e1).add(proof.A2)
    val hz1 = pubKey.multiply(proof.z1)
    val check2 = c2e1A2.equals(hz1)

    val e2 = new BigInteger(proof.e2)
    val c1e2B1 = ciphertext._1.multiply(e2).add(proof.B1)
    val gz2 = cs.basePoint.multiply(proof.z2)
    val check3 = c1e2B1.equals(gz2)

    val c2ge2B2 = ciphertext._2.subtract(cs.basePoint).multiply(e2).add(proof.B2)
    val hz2 = pubKey.multiply(proof.z2)
    val check4 = c2ge2B2.equals(hz2)

    check1 && check2 && check3 && check4
  }
}
