package treasury.crypto.nizk

import java.math.BigInteger

import treasury.crypto.core._

object DecryptionShareNIZK {

  case class DecryptionShareNIZKProof(A1: Point, A2: Point, z: Element) {
    def size: Int = {
      A1.getEncoded(true).length +
      A2.getEncoded(true).length +
      z.toByteArray.length
    }
  }

  def produceNIZK(
    cs: Cryptosystem,
    share: Point,
    privKey: PrivKey
  ): DecryptionShareNIZKProof = {
    val w = cs.getRand
    val A1 = cs.basePoint.multiply(w)
    val A2 = share.multiply(w)
    val D = share.multiply(privKey)

    val e = new BigInteger(
      cs.hash256 {
        share.getEncoded(true) ++
        D.getEncoded(true) ++
        A1.getEncoded(true) ++
        A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val z = privKey.multiply(e).add(w).mod(cs.orderOfBasePoint)

    DecryptionShareNIZKProof(A1.normalize(), A2.normalize(), z)
  }

  def verifyNIZK(
    cs: Cryptosystem,
    pubKey: PubKey,
    share: Point,
    decryptedShare: Point,
    proof: DecryptionShareNIZKProof
  ): Boolean = {

    val e = new BigInteger(
      cs.hash256 {
          share.getEncoded(true) ++
          decryptedShare.getEncoded(true) ++
          proof.A1.getEncoded(true) ++
          proof.A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val gz = cs.basePoint.multiply(proof.z)
    val heA1 = pubKey.multiply(e).add(proof.A1)

    val C1z = share.multiply(proof.z)
    val DeA2 = decryptedShare.multiply(e).add(proof.A2)

    gz.equals(heA1) && C1z.equals(DeA2)
  }
}

