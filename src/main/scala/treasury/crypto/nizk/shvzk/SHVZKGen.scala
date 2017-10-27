package treasury.crypto.nizk.shvzk

import java.math.BigInteger

import treasury.crypto._
import treasury.crypto.math.BigIntPolynomial

/* This class implements generation of Simple Honest Verifier Zero Knowledge proof for unit vector */
class SHVZKGen(cs: EllipticCurveCryptosystem,
               pubKey: PubKey,
               unitVector: Seq[Ciphertext],
               val choiceIndex: Int,
               val witnesses: Seq[Randomness]) extends SHVZKCommon(cs, pubKey, unitVector){

  class Commitment(val idxBit: Byte) {
    assert(idxBit == 0 || idxBit == 1)
    val ik = Array(idxBit)
    val alpha = cs.getRand()
    val beta = cs.getRand()
    val gamma = cs.getRand()
    val delta = cs.getRand()

    val E = cs.pedersenCommitment(crs, ik, alpha)
    val B = cs.pedersenCommitment(crs, beta, gamma)
    val A = cs.pedersenCommitment(crs, cs.multiplyScalars(ik, beta), delta)
  }

  class Polinoms(val comm: Commitment) {
    private val f_1_coeffs = Array(
      new BigInteger(comm.beta),          // free element
      new BigInteger(comm.ik)             // x coeff (first degree)
    ) ++ Array.fill[BigInteger](log - 1)(BigInteger.valueOf(0)) // other coeffs equal zero (there should be log + 1 coeffs)
    private val f_0_coeffs = Array(
      new BigInteger(comm.beta).negate,                                        // free element
      if (comm.idxBit == 0) BigInteger.valueOf(1) else BigInteger.valueOf(0)     // x coeff (first degree)
    ) ++ Array.fill[BigInteger](log - 1)(BigInteger.valueOf(0)) // other coeffs equal zero (there should be log + 1 coeffs)

    val f = Array(
      new BigIntPolynomial(f_0_coeffs),  // f_0 = (1-ik)*x - beta
      new BigIntPolynomial(f_1_coeffs)   // f_1 = ik*x + beta
    )
  }

  assert(unitVector.size > choiceIndex)
  assert(unitVector.size == witnesses.size)

  def produceNIZK() = {
    /* We want a unit vector to be the size of perfect power of 2. So pad unit vector with Enc(0,0) if it is not. */
    val rand = padRandVector(witnesses)

    /* Binary array representation of the index of the nonzero element in the unit vector */
    val idx = SHVZKCommon.intToBinArray(choiceIndex, log)
    assert(idx.size == log)

    /* Prepare commitments for each bit of the index */
    val commitments = for (i <- 0 until log) yield new Commitment(idx(i))

    /* Compute first verifier challenge */
    val statement = unitVector.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c._1 ++ c._2
    }
    val commitment = commitments.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c.E ++ c.B ++ c.A
    }
    val y = cs.hash256(pubKey ++ statement ++ commitment)
    val Y = new BigInteger(y)


    /* Prepare polinoms f_1 = ik*x+beta ; f_2 = x-f_1 for each bit of index */
    val polinoms = for (i <- 0 until log) yield new Polinoms(commitments(i))

    val Pj =
      for (i <- 0 until uvSize) yield {
        val j = SHVZKCommon.intToBinArray(i, log)
        var acc = polinoms(0).f(j(0))
        for (k <- 1 until log) {
          val t = polinoms(k).f(j(k))
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
            acc = Y.pow(j).multiply(Pj(j)(i)).add(acc)
          }
          acc
        }.mod(cs.orderOfBasePoint)

        (cs.encrypt(pubKey, Rk, sum.toByteArray), new BigInteger(Rk))
      }

    /* Compute second verifier challenge */
    val x = {
      val commitment2 = Dk.foldLeft(Array[Byte]()) {
        (acc, d) => acc ++ d._1._1 ++ d._1._2
      }
      cs.hash256(pubKey ++ statement ++ commitment ++ commitment2)
    }
    val X = new BigInteger(x)

    /* Compute f,w,v */
    val fwv =
      for (i <- 0 until log) yield {
        val beta = new BigInteger(commitments(i).beta)
        val gamma = new BigInteger(commitments(i).gamma)
        val alpha = new BigInteger(commitments(i).alpha)
        val delta = new BigInteger(commitments(i).delta)

        val f = {
          if (commitments(i).idxBit == 1)
            X.add(beta) // fk = ik*x + beta = x + beta (if ik = 1)
          else
            beta // fk = ik*x + beta = beta (if ik = 0)
        }.mod(cs.orderOfBasePoint)

        val w = alpha.multiply(X).add(gamma).mod(cs.orderOfBasePoint)             // wk = alpha*x + gamma (mod n)
        val v = X.subtract(f).multiply(alpha).add(delta).mod(cs.orderOfBasePoint) // v = alpha*(x-f)+delta (mod n)

        (f,w,v)
      }

    /* Compute R */
    val R = {
      var sum1 = BigInteger.valueOf(0)
      for (i <- 0 until uvSize) {
        val xpow = X.pow(log).mod(cs.orderOfBasePoint)
        val ypow = Y.pow(i).mod(cs.orderOfBasePoint)
        val ri = new BigInteger(rand(i))
        sum1 = sum1.add(ri.multiply(xpow).multiply(ypow).mod(cs.orderOfBasePoint))
      }

      var sum2 = BigInteger.valueOf(0)
      for (i <- 0 until log) {
        val xpow = X.pow(i).mod(cs.orderOfBasePoint)
        val Rk = Dk(i)._2
        sum2 = sum2.add(Rk.multiply(xpow)).mod(cs.orderOfBasePoint)
      }

      sum1.add(sum2)./*subtract(sum2).*/mod(cs.orderOfBasePoint)
    }

    /* Pack all data that is a part of public proof */
    new SHVZKProof(
      commitments.map(c => (c.E, c.B, c.A)),
      Dk.map(t => t._1),
      fwv.map(t => (t._1.toByteArray, t._2.toByteArray, t._3.toByteArray)),
      R.toByteArray
    )
  }
}
