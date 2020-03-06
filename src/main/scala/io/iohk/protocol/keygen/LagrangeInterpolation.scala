package io.iohk.protocol.keygen

import java.security.SecureRandom

import io.iohk.core.crypto.encryption.hybrid.HybridPlaintext
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.datastructures.round4.OpenedShare

object LagrangeInterpolation {
  private def getLagrangeCoeff(ctx: CryptoContext, x: Int, shares: Seq[OpenedShare]): BigInt = {
    import ctx.group
    var coeff = BigInt(1)

    for(j <- shares.indices) {
      if((shares(j).receiverID + 1) != x)
      {
        val J = BigInt(shares(j).receiverID.toLong + 1)
        val I = BigInt(x.toLong)

        val J_I = (J - I).mod(group.groupOrder)
        val JdivJ_I = (J * J_I.modInverse(group.groupOrder)).mod(group.groupOrder)

        coeff = (coeff * JdivJ_I).mod(group.groupOrder)
      }
    }
    coeff
  }

  def restoreSecret(ctx: CryptoContext, shares_in: Seq[OpenedShare], threshold: Int = 0): BigInt = {
    val shares = shares_in.take(if(threshold != 0) threshold else shares_in.length)

    var restoredSecret = BigInt(0)
    for(i <- shares.indices) {
      val L_i = getLagrangeCoeff(ctx, shares(i).receiverID + 1, shares)
      val p_i = BigInt(shares(i).S.decryptedMessage)

      restoredSecret = restoredSecret + (L_i * p_i) mod(ctx.group.groupOrder)
    }
    restoredSecret
  }

  def testInterpolation(ctx: CryptoContext, degree: Int): Boolean = {
    val secret = BigInt(ctx.group.groupOrder.bitLength, new SecureRandom()).mod(ctx.group.groupOrder)
    val poly = new Polynomial(ctx, secret, degree)

    val sharesNum = degree * 2 // ratio specific for voting protocol, as assumed t = n / 2, i.e. degree = sharesNum / 2
    var shares = for(x <- 0 until sharesNum) yield {OpenedShare(x, HybridPlaintext(ctx.group.groupIdentity, poly.evaluate(x+1).toByteArray))}

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

    val restoredSecret = restoreSecret(ctx, shares, degree)

    secret.equals(restoredSecret)
  }
}
