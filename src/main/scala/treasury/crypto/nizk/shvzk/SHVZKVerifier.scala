package treasury.crypto.nizk.shvzk

import java.math.BigInteger
import java.util

import treasury.crypto._

class SHVZKVerifier(cs: Cryptosystem,
                    pubKey: PubKey,
                    unitVector: Seq[Ciphertext],
                    val proof: SHVZKProof) extends SHVZKCommon(cs, pubKey, unitVector) {

  private val statement = unitVector.foldLeft(Array[Byte]()) {
    (acc, c) => acc ++ c._1.getEncoded(true) ++ c._2.getEncoded(true)
  }
  private val commitment = proof.IBA.foldLeft(Array[Byte]()) {
    (acc, c) => acc ++ c._1.getEncoded(true) ++ c._2.getEncoded(true) ++ c._3.getEncoded(true)
  }

  /* Compute first verifier challange */
  private val y = {
    cs.hash256(pubKey.getEncoded(true) ++ statement ++ commitment)
  }
  private val Y = new BigInteger(y)

  /* Compute second verifier challange */
  private val x = {
    val commitment2 = proof.Dk.foldLeft(Array[Byte]()) {
      (acc, d) => acc ++ d._1.getEncoded(true) ++ d._2.getEncoded(true)
    }
    cs.hash256(pubKey.getEncoded(true) ++ statement ++ commitment ++ commitment2)
  }
  private val X = new BigInteger(x)


  def verifyProof(): Boolean = {
    /* Sanity check of proof */
    if (proof.IBA.size != log) return false
    if (proof.Dk.size != log) return false
    if (proof.zwv.size != log) return false

    /* The size of unit vector has to be perfect power of 2. So pad unit vector with Enc(0,0) if it is necessary. */
    val uv = padUnitVector(unitVector)

    val res1 = checkCommitments(proof.IBA, proof.zwv)
    val res2 = checkUnitVector(uv, proof.Dk, proof.zwv.map(_._1), proof.R)

    res1 && res2
  }

  private def checkCommitments(IBA: Seq[(Point, Point, Point)], zwv: Seq[(Element, Element, Element)]): Boolean = {
    for (i <- 0 until log) {
      val (_I,_B,_A) = (IBA(i)._1, IBA(i)._2, IBA(i)._3)
      val (z,w,v) = (zwv(i)._1, zwv(i)._2, zwv(i)._3)

      /* 1 check (I^x * B == Com(z;w)) */
      val com = pedersenCommitment(crs, z, w)
      val Ix = _I.multiply(X)
      val IxB = Ix.add(_B)
      if (!IxB.equals(com)) return false

      /* 2 check (I^(x-z)*A == Com(0,v) */
      val com2 = pedersenCommitment(crs, Zero, v)
      val p = X.subtract(z).mod(cs.orderOfBasePoint)
      val Ixz = _I.multiply(p)
      val IxzA = Ixz.add(_A)
      if (!IxzA.equals(com2)) return false
    }

    true
  }

  private def checkUnitVector(uv: Seq[Ciphertext], Dk: Seq[Ciphertext], z: Seq[Element], R: Element): Boolean = {
    val x_pow_log = X.pow(log).mod(cs.orderOfBasePoint)

    var mult1: Ciphertext = null
    for (i <- 0 until uvSize) {
      val idx = SHVZKCommon.intToBinArray(i, log)
      var multz = One
      for (j <- 0 until log) {
        val m = if (idx(j) == 1) z(j) else X.subtract(z(j))
        multz = multz.multiply(m).mod(cs.orderOfBasePoint)
      }
      val enc = cs.encrypt(pubKey, Zero, multz.negate)
      val multC = cs.multiply(uv(i), x_pow_log)
      val y_pow_i = Y.pow(i).mod(cs.orderOfBasePoint)
      val t = cs.multiply(cs.add(multC, enc), y_pow_i)

      mult1 match {
        case null => mult1 = t
        case c: Ciphertext => mult1 = cs.add(c, t)
      }
    }

    var multD = cs.multiply(Dk(0), X.pow(0))
    for (i <- 1 until log) {
      val xpow = X.pow(i).mod(cs.orderOfBasePoint)
      multD = cs.add(multD, cs.multiply(Dk(i), xpow))
    }

    val check = cs.add(mult1, multD)
    val com = cs.encrypt(pubKey, R, Zero)

    check._1.equals(com._1) && check._2.equals(com._2)
  }
}
