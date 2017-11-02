package treasury.crypto.keygen

import java.math.BigInteger
import java.security.SecureRandom

import treasury.crypto.core.Cryptosystem

object LagrangeInterpolation
{
  private def getLagrangeCoeff(cs: Cryptosystem, x: Integer, shares: Seq[SecretShare]): BigInteger =
  {
    var coeff = new BigInteger("1")

    for(j <- shares.indices)
    {
      if(shares(j).x != x)
      {
        val J = BigInteger.valueOf(shares(j).x.toLong)
        val I = BigInteger.valueOf(x.toLong)

        val J_I = J.subtract(I).mod(cs.orderOfBasePoint)
        val JdivJ_I = J.multiply(J_I.modInverse(cs.orderOfBasePoint)).mod(cs.orderOfBasePoint)

        coeff = coeff.multiply(JdivJ_I).mod(cs.orderOfBasePoint)
      }
    }
    coeff
  }

  def restoreSecret(cs: Cryptosystem, shares: Seq[SecretShare]): BigInteger =
  {
    var restoredSecret = new BigInteger("0")
    for(i <- shares.indices)
    {
      val L_i = getLagrangeCoeff(cs, shares(i).x, shares)
      val p_i = new BigInteger(shares(i).S)

      restoredSecret = restoredSecret.add(L_i.multiply(p_i)).mod(cs.orderOfBasePoint)
    }
    restoredSecret
  }

  def testInterpolation(cs: Cryptosystem, degree: Int): Boolean =
  {
    val secret = new BigInteger(cs.orderOfBasePoint.bitLength(), new SecureRandom()).mod(cs.orderOfBasePoint)
    val poly = new Polynomial(cs, secret, degree)

    val sharesNum = degree * 2 // ratio specific for voting protocol, as assumed t = n / 2, i.e. degree = sharesNum / 2
    var shares = for(x <- 1 to sharesNum) yield {SecretShare(0, x, poly(BigInteger.valueOf(x)).toByteArray)}

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

    val restoredSecret = restoreSecret(cs, shares)

    secret.equals(restoredSecret)
  }
}
