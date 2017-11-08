package treasury.crypto.nizk.shvzk

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.math.BigIntPolynomial

/* This class implements generation of Special Honest Verifier Zero Knowledge proof for unit vector */
class SHVZKGen(cs: Cryptosystem,
               pubKey: PubKey,
               unitVector: Seq[Ciphertext],
               val choiceIndex: Int,
               val randomness: Seq[Randomness]) extends SHVZKCommon(cs, pubKey, unitVector){

  private class Commitment(val idxBit: Byte) {
    assert(idxBit == 0 || idxBit == 1)
    val ik = BigInteger.valueOf(idxBit)
    val alpha = cs.getRand
    val beta = cs.getRand
    val gamma = cs.getRand
    val delta = cs.getRand

    val I = pedersenCommitment(crs, ik, alpha)
    val B = pedersenCommitment(crs, beta, gamma)
    val A = pedersenCommitment(crs, ik.multiply(beta), delta)
  }

  private class Polinoms(val comm: Commitment) {
    private val z_1_coeffs =
      Array(comm.beta, comm.ik) ++            // z_1 = ik*x + beta
      Array.fill[BigInteger](log - 1)(Zero)   // other coeffs equal zero (there should be log + 1 coeffs)

    private val z_0_coeffs =
      Array(comm.beta.negate, One.subtract(comm.ik)) ++     // z_0 = x-z_1 = (1-ik)*x - beta
      Array.fill[BigInteger](log - 1)(Zero)            // other coeffs equal zero (there should be log + 1 coeffs)

    val z = Array(
      new BigIntPolynomial(z_0_coeffs),  // z_0 = (1-ik)*x - beta
      new BigIntPolynomial(z_1_coeffs)   // z_1 = ik*x + beta
    )
  }

  assert(unitVector.size > choiceIndex)
  assert(unitVector.size == randomness.size)

  def produceNIZK() = {
    /* We want a unit vector to be the size of perfect power of 2. So pad unit vector with Enc(0,0) if it is not.
     * Actually for NIZK generation we need only to pad randomness because we will not hash padded elements during
     * challenges calculation */
    val rand = padRandVector(randomness)

    /* Binary array representation of the index of the nonzero element in the unit vector */
    val idx = SHVZKCommon.intToBinArray(choiceIndex, log)
    assert(idx.size == log)

    /* Step 1. Prepare commitments (I,B,A) for each bit of the index */
    val commitments = for (i <- 0 until log) yield new Commitment(idx(i))

    /* Step 2. Compute first verifier challenge */
    val statement = unitVector.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c._1.getEncoded(true) ++ c._2.getEncoded(true)
    }
    val commitment = commitments.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c.I.getEncoded(true) ++ c.B.getEncoded(true) ++ c.A.getEncoded(true)
    }
    val y = cs.hash256(pubKey.getEncoded(true) ++ statement ++ commitment)
    val Y = new BigInteger(y)

    /* Step 3. Compute Dk */
    val Dk = computeDk(commitments, Y)

    /* Step 4. Compute second verifier challenge */
    val x = {
      val commitment2 = Dk.foldLeft(Array[Byte]()) {
        (acc, d) => acc ++ d._1._1.getEncoded(true) ++ d._1._2.getEncoded(true)
      }
      cs.hash256(pubKey.getEncoded(true) ++ statement ++ commitment ++ commitment2)
    }
    val X = new BigInteger(x)

    /* Step 5. Compute z,w,v */
    val zwv = computeZwv(commitments, X)

    /* Step 6. Compute R */
    val R = computeR(Y, X, rand, Dk.map(_._2))

    /* Pack all data for public proof */
    new SHVZKProof(
      commitments.map(c => (c.I, c.B, c.A)),
      Dk.map(t => t._1),
      zwv,
      R
    )
  }

  private def computeDk(commitments: Seq[Commitment], y: BigInteger): Seq[(Ciphertext, BigInteger)] = {
    /* Prepare polinoms f_1 = ik*x+beta ; f_2 = x-f_1 for each bit of index */
    val polinoms = for (i <- 0 until log) yield new Polinoms(commitments(i))

    /* Prepare Pj polinoms where top level coefficient P(j,l) is the multiplication of the bits of the index.
     * Pj = (B1*B2*..*Bk)*x^log(l) + P(j,l-1)*x^log(l)-1 + ... + P(j,0) */
    val Pj =
      for (i <- 0 until uvSize) yield {
        val j = SHVZKCommon.intToBinArray(i, log)
        var acc = polinoms(0).z(j(0))
        for (k <- 1 until log) {
          val t = polinoms(k).z(j(k))
          acc = acc.mult(t)
        }
        acc.mod(cs.orderOfBasePoint)
        acc.getCoeffs
      }

    /* Prepare Dk elements for proofs */
    val Dk =
      for (i <- 0 until log) yield {
        val sum = {
          var acc = Zero
          for (j <- 0 until uvSize) {
            acc = y.pow(j).multiply(Pj(j)(i)).add(acc)
          }
          acc
        }.mod(cs.orderOfBasePoint)

        val Rk = cs.getRand
        (cs.encrypt(pubKey, Rk, sum), Rk)
      }

    Dk
  }

  private def computeZwv(commitments: Seq[Commitment], x: BigInteger): Seq[(BigInteger, BigInteger, BigInteger)] = {
    val zwv =
      for (i <- 0 until log) yield {
        val beta = commitments(i).beta
        val gamma = commitments(i).gamma
        val alpha = commitments(i).alpha
        val delta = commitments(i).delta

        val z = {
          if (commitments(i).idxBit == 1)
            x.add(beta) // z = ik*x + beta = x + beta (if ik = 1)
          else
            beta        // z = ik*x + beta = beta (if ik = 0)
        }.mod(cs.orderOfBasePoint)

        val w = alpha.multiply(x).add(gamma).mod(cs.orderOfBasePoint)             // wk = alpha*x + gamma (mod n)
        val v = x.subtract(z).multiply(alpha).add(delta).mod(cs.orderOfBasePoint) // v = alpha*(x-z)+delta (mod n)

        (z,w,v)
      }
    zwv
  }

  def computeR(y: BigInteger, x: BigInteger, rand: Seq[Randomness], Rk: Seq[Randomness]): BigInteger = {
    var sum1 = Zero
    val xpow = x.pow(log).mod(cs.orderOfBasePoint)
    for (i <- 0 until uvSize) {
      val ypow = y.pow(i).mod(cs.orderOfBasePoint)
      sum1 = sum1.add(rand(i).multiply(xpow).multiply(ypow))
    }

    var sum2 = Zero
    for (i <- 0 until log) {
      val xpow = x.pow(i).mod(cs.orderOfBasePoint)
      sum2 = sum2.add(Rk(i).multiply(xpow))
    }

    sum1.add(sum2).mod(cs.orderOfBasePoint)
  }
}
