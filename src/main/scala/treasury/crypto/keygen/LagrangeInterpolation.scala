package treasury.crypto.keygen

import java.math.BigInteger
import java.security.SecureRandom

import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.HybridPlaintext
import treasury.crypto.keygen.datastructures.round4.OpenedShare

object LagrangeInterpolation {
  private def getLagrangeCoeff(cs: Cryptosystem, x: Integer, shares: Seq[OpenedShare]): BigInt = {
    var coeff = BigInt(1)

    for(j <- shares.indices) {
      if((shares(j).receiverID + 1) != x)
      {
        val J = BigInt(shares(j).receiverID.toLong + 1)
        val I = BigInt(x.toLong)

        val J_I = (J - I).mod(cs.orderOfBasePoint)
        val JdivJ_I = (J * J_I.modInverse(cs.orderOfBasePoint)).mod(cs.orderOfBasePoint)

        coeff = (coeff * JdivJ_I).mod(cs.orderOfBasePoint)
      }
    }
    coeff
  }

  def restoreSecret(cs: Cryptosystem, shares_in: Seq[OpenedShare], threshold: Int = 0): BigInt = {
    val shares = shares_in.take(if(threshold != 0) threshold else shares_in.length)

    var restoredSecret = BigInt(0)
    for(i <- shares.indices) {
      val L_i = getLagrangeCoeff(cs, shares(i).receiverID + 1, shares)
      val p_i = BigInt(shares(i).S.decryptedMessage)

      restoredSecret = restoredSecret + (L_i * p_i) mod(cs.orderOfBasePoint)
    }
    restoredSecret
  }

  def testInterpolation(cs: Cryptosystem, degree: Int): Boolean = {
    val secret = BigInt(cs.orderOfBasePoint.bitLength, new SecureRandom()).mod(cs.orderOfBasePoint)
    val poly = new Polynomial(cs, secret, degree)

    val sharesNum = degree * 2 // ratio specific for voting protocol, as assumed t = n / 2, i.e. degree = sharesNum / 2
    var shares = for(x <- 0 until sharesNum) yield {OpenedShare(x, HybridPlaintext(cs.infinityPoint, poly.evaluate(x+1).toByteArray))}

    val rnd = new scala.util.Random
    val patchIndex = rnd.nextInt(sharesNum)
    val patchLength = {
      val maxLength = sharesNum - patchIndex
      if(maxLength > degree) // the minimal number of shares needed for interpolation is equal to degree of polynomial
        rnd.nextInt(degree)
      else
        rnd.nextInt(maxLength)
    } + 1

    // Delete random number of shares (imitation of committee members disqualification)
    shares = shares.patch(patchIndex, Nil, patchLength)

    val restoredSecret = restoreSecret(cs, shares, degree)

    secret.equals(restoredSecret)
  }
}
