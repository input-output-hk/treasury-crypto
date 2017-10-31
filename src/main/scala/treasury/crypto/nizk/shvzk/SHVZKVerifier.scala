package treasury.crypto.nizk.shvzk

import java.math.BigInteger
import java.util

import treasury.crypto._

class SHVZKVerifier(cs: Cryptosystem,
                    pubKey: PubKey,
                    unitVector: Seq[Ciphertext],
                    val proof: SHVZKProof) extends SHVZKCommon(cs, pubKey, unitVector) {

  private val statement = unitVector.foldLeft(Array[Byte]()) {
    (acc, c) => acc ++ c._1 ++ c._2
  }
  private val commitment = proof.IBA.foldLeft(Array[Byte]()) {
    (acc, c) => acc ++ c._1 ++ c._2 ++ c._3
  }

  /* Compute first verifier challange */
  private val y = {
    cs.hash256(pubKey ++ statement ++ commitment)
  }
  private val Y = new BigInteger(y)

  /* Compute second verifier challange */
  private val x = {
    val commitment2 = proof.Dk.foldLeft(Array[Byte]()) {
      (acc, d) => acc ++ d._1 ++ d._2
    }
    cs.hash256(pubKey ++ statement ++ commitment ++ commitment2)
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
      val com = cs.pedersenCommitment(crs, z, w)
      val Ix = cs.multiply(_I, x)
      val IxB = cs.add(Ix, _B)
      if (!util.Arrays.equals(IxB, com)) return false

      /* 2 check (I^(x-z)*A == Com(0,v) */
      val com2 = cs.pedersenCommitment(crs, Array(0), v)
      val p = new BigInteger(x).subtract(new BigInteger(z)).mod(cs.orderOfBasePoint)
      val Ixz = cs.multiply(_I, p.toByteArray)
      val IxzA = cs.add(Ixz, _A)
      if (!util.Arrays.equals(IxzA, com2)) return false
    }

    true
  }

  private def checkUnitVector(uv: Seq[Ciphertext], Dk: Seq[Ciphertext], z: Seq[Element], R: Element): Boolean = {
    val x_pow_log = X.pow(log).mod(cs.orderOfBasePoint).toByteArray

    var mult1: Ciphertext = null
    for (i <- 0 until uvSize) {
      val idx = SHVZKCommon.intToBinArray(i, log)
      var multz = BigInteger.valueOf(1)
      for (j <- 0 until log) {
        val m = if (idx(j) == 1) new BigInteger(z(j)) else X.subtract(new BigInteger(z(j))).mod(cs.orderOfBasePoint)
        multz = multz.multiply(m).mod(cs.orderOfBasePoint)
      }
      val enc = cs.encrypt(pubKey, Array(0.toByte), multz.negate.mod(cs.orderOfBasePoint).toByteArray)
      val multC = cs.multiply(uv(i), x_pow_log)
      val y_pow_i = Y.pow(i).mod(cs.orderOfBasePoint).toByteArray
      val t = cs.multiply(cs.add(multC, enc), y_pow_i)

      mult1 match {
        case null => mult1 = t
        case c: Ciphertext => mult1 = cs.add(c, t)
      }
    }

    var multD = cs.multiply(Dk(0), X.pow(0)/*.negate*/.mod(cs.orderOfBasePoint).toByteArray)
    for (i <- 1 until log) {
      val xpow = X.pow(i)/*.negate*/.mod(cs.orderOfBasePoint).toByteArray
      multD = cs.add(multD, cs.multiply(Dk(i), xpow))
    }

    val check = cs.add(mult1, multD)
    val com = cs.encrypt(pubKey, R, Array(0.toByte))

    util.Arrays.equals(check._1, com._1) && util.Arrays.equals(check._2, com._2)
  }
}
