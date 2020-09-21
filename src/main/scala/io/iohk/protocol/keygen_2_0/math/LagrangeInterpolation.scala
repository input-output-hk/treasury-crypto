package io.iohk.protocol.keygen_2_0.math

import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.datastructures.Share

object LagrangeInterpolation {

  def getLagrangeCoeff(ctx: CryptoContext, x: Int, x_all: Seq[Int], eval_point: Int = 0): BigInt = {
    import ctx.group

    val I = BigInt(x.toLong)
    val EP = BigInt(eval_point.toLong)
    val n = group.groupOrder

    x_all.foldLeft(BigInt(1)){
      (lambda, x_i) =>
        if(x_i != x)
        {
          val J = BigInt(x_i)

          val J_minus_EP = (J - EP).mod(n)
          val J_minus_I = (J - I).mod(n)

          (lambda * (J_minus_EP * J_minus_I.modInverse(n)).mod(n)).mod(n)
        } else {
          lambda
        }
    }
  }

  def restoreSecret(context: CryptoContext, shares_in: Seq[Share], threshold: Int = 0): BigInt = {
    val shares = shares_in.take(if(threshold != 0) threshold else shares_in.length)
    val all_points = shares.map(_.point)

    shares.foldLeft(BigInt(0)){
      (sum, share) =>
        val lambda = LagrangeInterpolation.getLagrangeCoeff(context, share.point, all_points)
        (sum + (lambda * share.value)).mod(context.group.groupOrder)
    }
  }
}
