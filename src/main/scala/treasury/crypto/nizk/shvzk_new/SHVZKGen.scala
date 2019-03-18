package treasury.crypto.nizk.shvzk_new

import treasury.crypto.core.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import treasury.crypto.core.encryption.encryption.{PubKey, Randomness}
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.primitives.hash.CryptographicHash
import treasury.crypto.math.BigIntPolynomial

import scala.util.Try

/* This class implements generation of Special Honest Verifier Zero Knowledge proof for unit vector */
class SHVZKGen(pubKey: PubKey,
               unitVector: Seq[ElGamalCiphertext],
               choiceIndex: Int,
               randomness: Seq[Randomness])
              (override implicit val dlog: DiscreteLogGroup,
               override implicit val hashFunction: CryptographicHash) extends SHVZKCommon(pubKey, unitVector) {

  private class Commitment(val idxBit: Byte) {
    assert(idxBit == 0 || idxBit == 1)
    val ik = BigInt(idxBit)
    val alpha = dlog.createRandomNumber
    val beta = dlog.createRandomNumber
    val gamma = dlog.createRandomNumber
    val delta = dlog.createRandomNumber

    val I = pedersenCommitment(crs, ik, alpha).get
    val B = pedersenCommitment(crs, beta, gamma).get
    val A = pedersenCommitment(crs, ik * beta, delta).get
  }

  private class Polinoms(val comm: Commitment) {
    private val z_1_coeffs =
      Array(comm.beta, comm.ik) ++                  // z_1 = ik*x + beta
      Array.fill[BigInt](log - 1)(0)         // other coeffs equal zero (there should be log + 1 coeffs)

    private val z_0_coeffs =
      Array(-comm.beta, 1 - comm.ik) ++             // z_0 = x-z_1 = (1-ik)*x - beta
      Array.fill[BigInt](log - 1)(0)         // other coeffs equal zero (there should be log + 1 coeffs)

    val z = Array(
      new BigIntPolynomial(z_0_coeffs.map(_.bigInteger)),  // z_0 = (1-ik)*x - beta
      new BigIntPolynomial(z_1_coeffs.map(_.bigInteger))   // z_1 = ik*x + beta
    )
  }

  require(unitVector.size > choiceIndex)
  require(unitVector.size == randomness.size)

  def produceNIZK(): Try[SHVZKProof] = Try {
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
      (acc, c) => acc ++ c.c1.bytes ++ c.c2.bytes
    }
    val commitment = commitments.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c.I.bytes ++ c.B.bytes ++ c.A.bytes
    }
    val y = hashFunction.hash(pubKey.bytes ++ statement ++ commitment)
    val Y = BigInt(1, y)

    /* Step 3. Compute Dk */
    val Dk = computeDk(commitments, Y)

    /* Step 4. Compute second verifier challenge */
    val x = {
      val commitment2 = Dk.foldLeft(Array[Byte]()) {
        (acc, d) => acc ++ d._1.c1.bytes ++ d._1.c2.bytes
      }
      hashFunction.hash(pubKey.bytes ++ statement ++ commitment ++ commitment2)
    }
    val X = BigInt(1, x)

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

  private def computeDk(commitments: Seq[Commitment], y: BigInt): Seq[(ElGamalCiphertext, BigInt)] = {
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
        acc.mod(dlog.groupOrder.bigInteger)
        acc.getCoeffs
      }

    /* Prepare Dk elements for proofs */
    val Dk =
      for (i <- 0 until log) yield {
        val sum = {
          var acc = BigInt(0)
          for (j <- 0 until uvSize) {
            acc = y.pow(j) * Pj(j)(i) + acc
          }
          acc
        }.mod(dlog.groupOrder)

        val Rk = dlog.createRandomNumber
        (LiftedElGamalEnc.encrypt(pubKey, Rk, sum).get, Rk)
      }

    Dk
  }

  private def computeZwv(commitments: Seq[Commitment], x: BigInt): Seq[(BigInt, BigInt, BigInt)] = {
    val zwv =
      for (i <- 0 until log) yield {
        val beta = commitments(i).beta
        val gamma = commitments(i).gamma
        val alpha = commitments(i).alpha
        val delta = commitments(i).delta

        val z = {
          if (commitments(i).idxBit == 1)
            x + beta    // z = ik*x + beta = x + beta (if ik = 1)
          else
            beta        // z = ik*x + beta = beta (if ik = 0)
        }.mod(dlog.groupOrder)

        val w = (alpha * x + gamma).mod(dlog.groupOrder)             // wk = alpha*x + gamma (mod n)
        val v = ((x - z) * alpha + delta).mod(dlog.groupOrder)       // v = alpha*(x-z)+delta (mod n)

        (z,w,v)
      }
    zwv
  }

  def computeR(y: BigInt, x: BigInt, rand: Seq[Randomness], Rk: Seq[Randomness]): BigInt = {
    var sum1 = BigInt(0)
    val xpow = x.pow(log).mod(dlog.groupOrder)
    for (i <- 0 until uvSize) {
      val ypow = y.pow(i).mod(dlog.groupOrder)
      sum1 = sum1 + (rand(i) * xpow * ypow)
    }

    var sum2 = BigInt(0)
    for (i <- 0 until log) {
      val xpow = x.pow(i).mod(dlog.groupOrder)
      sum2 = sum2 + (Rk(i) * xpow)
    }

    (sum1 + sum2).mod(dlog.groupOrder)
  }
}
