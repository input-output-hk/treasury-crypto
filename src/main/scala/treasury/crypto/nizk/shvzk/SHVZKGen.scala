package treasury.crypto.nizk.shvzk

import java.math.BigInteger

import treasury.crypto._
import treasury.crypto.math.BigIntPolynomial

/* This class implements generation of Special Honest Verifier Zero Knowledge proof for unit vector */
class SHVZKGen(cs: Cryptosystem,
               pubKey: PubKey,
               unitVector: Seq[Ciphertext],
               val choiceIndex: Int,
               val randomness: Seq[Randomness]) extends SHVZKCommon(cs, pubKey, unitVector){

  private class Commitment(val idxBit: Byte) {
    assert(idxBit == 0 || idxBit == 1)
    val ik = Array(idxBit)
    val alpha = cs.getRand()
    val beta = cs.getRand()
    val gamma = cs.getRand()
    val delta = cs.getRand()

    val I = cs.pedersenCommitment(crs, ik, alpha)
    val B = cs.pedersenCommitment(crs, beta, gamma)
    val A = cs.pedersenCommitment(crs, cs.multiplyScalars(ik, beta), delta)
  }

  private class Polinoms(val comm: Commitment) {
    private val z_1_coeffs = Array(
      new BigInteger(comm.beta),          // free element
      new BigInteger(comm.ik)             // x coeff (first degree)
    ) ++ Array.fill[BigInteger](log - 1)(BigInteger.valueOf(0)) // other coeffs equal zero (there should be log + 1 coeffs)
    private val z_0_coeffs = Array(
      new BigInteger(comm.beta).negate,                                        // free element
      if (comm.idxBit == 0) BigInteger.valueOf(1) else BigInteger.valueOf(0)     // x coeff (first degree)
    ) ++ Array.fill[BigInteger](log - 1)(BigInteger.valueOf(0)) // other coeffs equal zero (there should be log + 1 coeffs)

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
      (acc, c) => acc ++ c._1 ++ c._2
    }
    val commitment = commitments.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c.I ++ c.B ++ c.A
    }
    val y = cs.hash256(pubKey ++ statement ++ commitment)
    val Y = new BigInteger(y)

    /* Step 3. Compute Dk */
    val Dk = computeDk(commitments, Y)

    /* Step 4. Compute second verifier challenge */
    val x = {
      val commitment2 = Dk.foldLeft(Array[Byte]()) {
        (acc, d) => acc ++ d._1._1 ++ d._1._2
      }
      cs.hash256(pubKey ++ statement ++ commitment ++ commitment2)
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
      zwv.map(t => (t._1.toByteArray, t._2.toByteArray, t._3.toByteArray)),
      R.toByteArray
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
        val Rk = cs.getRand()
        val sum = {
          var acc = BigInteger.valueOf(0)
          for (j <- 0 until uvSize) {
            acc = y.pow(j).multiply(Pj(j)(i)).add(acc)
          }
          acc
        }.mod(cs.orderOfBasePoint)

        (cs.encrypt(pubKey, Rk, sum.toByteArray), new BigInteger(Rk))
      }
    Dk
  }

  private def computeZwv(commitments: Seq[Commitment], x: BigInteger): Seq[(BigInteger, BigInteger, BigInteger)] = {
    val zwv =
      for (i <- 0 until log) yield {
        val beta = new BigInteger(commitments(i).beta)
        val gamma = new BigInteger(commitments(i).gamma)
        val alpha = new BigInteger(commitments(i).alpha)
        val delta = new BigInteger(commitments(i).delta)

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

  def computeR(y: BigInteger, x: BigInteger, rand: Seq[Randomness], Rk: Seq[BigInteger]): BigInteger = {
    var sum1 = BigInteger.valueOf(0)
    for (i <- 0 until uvSize) {
      val xpow = x.pow(log).mod(cs.orderOfBasePoint)
      val ypow = y.pow(i).mod(cs.orderOfBasePoint)
      val ri = new BigInteger(rand(i))
      sum1 = sum1.add(ri.multiply(xpow).multiply(ypow).mod(cs.orderOfBasePoint))
    }

    var sum2 = BigInteger.valueOf(0)
    for (i <- 0 until log) {
      val xpow = x.pow(i).mod(cs.orderOfBasePoint)
      sum2 = sum2.add(Rk(i).multiply(xpow)).mod(cs.orderOfBasePoint)
    }

    sum1.add(sum2).mod(cs.orderOfBasePoint)
  }
}
