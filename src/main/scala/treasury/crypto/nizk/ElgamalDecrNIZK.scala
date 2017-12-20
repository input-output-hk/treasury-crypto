package treasury.crypto.nizk

import java.math.BigInteger

import treasury.crypto.core._

object ElgamalDecrNIZK {

  case class ElgamalDecrNIZKProof(A1: Point, A2: Point, z: Element) {
    def size: Int = {
      A1.getEncoded(true).size +
      A2.getEncoded(true).size +
      z.toByteArray.size
    }
  }

  def produceNIZK(
    cs: Cryptosystem,
    ciphertext: Ciphertext,
    privKey: PrivKey
  ): ElgamalDecrNIZKProof = {

    val w = cs.getRand
    val A1 = cs.basePoint.multiply(w)
    val A2 = ciphertext._1.multiply(w)
    val D = ciphertext._1.multiply(privKey)

    val e = new BigInteger(
      cs.hash256 {
        ciphertext._1.getEncoded(true) ++
        ciphertext._2.getEncoded(true) ++
        D.getEncoded(true) ++
        A1.getEncoded(true) ++
        A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val z = privKey.multiply(e).add(w).mod(cs.orderOfBasePoint)

    ElgamalDecrNIZKProof(A1.normalize(), A2.normalize(), z)
  }

  def verifyNIZK(
    cs: Cryptosystem,
    pubKey: PubKey,
    ciphertext: Ciphertext,
    plaintext: Point,
    proof: ElgamalDecrNIZKProof
  ): Boolean = {

    val D = ciphertext._2.subtract(plaintext)
    val e = new BigInteger(
      cs.hash256 {
        ciphertext._1.getEncoded(true) ++
          ciphertext._2.getEncoded(true) ++
          D.getEncoded(true) ++
          proof.A1.getEncoded(true) ++
          proof.A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val gz = cs.basePoint.multiply(proof.z)
    val heA1 = pubKey.multiply(e).add(proof.A1)

    val C1z = ciphertext._1.multiply(proof.z)
    val DeA2 = D.multiply(e).add(proof.A2)

    gz.equals(heA1) && C1z.equals(DeA2)
  }
}
