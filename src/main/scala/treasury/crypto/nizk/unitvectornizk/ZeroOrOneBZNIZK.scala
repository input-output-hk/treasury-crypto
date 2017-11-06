package treasury.crypto.nizk.unitvectornizk

import java.math.BigInteger

import treasury.crypto.core._

/* This class implements the protocol developed by prof. Bingsheng Zhang to prove that a ciphertext encrypts
 * zero or one. Ciphertext is obtained with Lifted Elgamal encryption scheme. */

object ZeroOrOneBZNIZK {
  case class ZeroOrOneBZNIZKProof(A: Ciphertext, B: Ciphertext, f: Element, w: Element, v: Element)

  def produceNIZK(cs: Cryptosystem,
                  pubKey: PubKey,
                  plaintext: BigInteger,
                  ciphertext: Ciphertext,
                  r: Randomness): ZeroOrOneBZNIZKProof = {
    val beta = cs.getRand
    val gamma = cs.getRand
    val delta = cs.getRand

    val B = cs.encrypt(pubKey, gamma, beta)
    val A = cs.encrypt(pubKey, delta, plaintext.multiply(beta))

    val e = new BigInteger(cs.hash256 {
      pubKey.getEncoded(true) ++
      ciphertext._1.getEncoded(true) ++
      ciphertext._2.getEncoded(true) ++
      B._1.getEncoded(true) ++
      B._2.getEncoded(true) ++
      A._1.getEncoded(true) ++
      A._2.getEncoded(true)
    }).mod(cs.orderOfBasePoint)

    val f = plaintext.multiply(e).add(beta)
    val w = r.multiply(e).add(gamma)
    val v = e.subtract(f).multiply(r).add(delta)

    ZeroOrOneBZNIZKProof(A, B, f, w, v)
  }

  def verifyNIZK(cs: Cryptosystem, pubKey: PubKey, ciphertext: Ciphertext, proof: ZeroOrOneBZNIZKProof): Boolean = {
    val e = new BigInteger(cs.hash256 {
      pubKey.getEncoded(true) ++
      ciphertext._1.getEncoded(true) ++
      ciphertext._2.getEncoded(true) ++
      proof.B._1.getEncoded(true) ++
      proof.B._2.getEncoded(true) ++
      proof.A._1.getEncoded(true) ++
      proof.A._2.getEncoded(true)
    }).mod(cs.orderOfBasePoint)

    val ceB = cs.add(cs.multiply(ciphertext, e), proof.B)
    val encfw = cs.encrypt(pubKey, proof.w, proof.f)
    val check1 = ceB._1.equals(encfw._1) && ceB._2.equals(encfw._2)

    val cefA = cs.add(cs.multiply(ciphertext, e.subtract(proof.f)), proof.A)
    val enc0v = cs.encrypt(pubKey, proof.v, Zero)
    val check2 = cefA._1.equals(enc0v._1) && cefA._2.equals(enc0v._2)

    check1 && check2
  }
}
