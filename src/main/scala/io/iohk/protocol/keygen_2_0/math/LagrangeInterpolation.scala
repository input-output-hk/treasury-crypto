package io.iohk.protocol.keygen_2_0.math

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.IdPointMap
import io.iohk.protocol.keygen_2_0.datastructures.Share

object LagrangeInterpolation {

  def getLagrangeCoeff(group: DiscreteLogGroup, x: Int, x_all: Seq[Int], eval_point: Int = 0): BigInt = {

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

  def restoreSecret(group: DiscreteLogGroup, shares_in: Seq[Share], threshold: Int = 0): BigInt = {
    val shares = shares_in.take(if(threshold != 0) threshold else shares_in.length)
    val all_points = shares.map(_.point)

    shares.foldLeft(BigInt(0)){
      (sum, share) =>
        val lambda = LagrangeInterpolation.getLagrangeCoeff(group, share.point, all_points)
        (sum + (lambda * share.value)).mod(group.groupOrder)
    }
  }

  def getShares(poly: Polynomial, evaluationPoints: Seq[Int]) : Seq[Share] = {
    evaluationPoints.map{
      point =>
        assert(point != 0) // avoid share for a_0 coefficient
        Share(point, poly.evaluate(point))
    }
  }

  def testInterpolation(ctx: CryptoContext, threshold: Int): Boolean = {

    val n = threshold * 2 // ratio specific for voting protocol, as assumed t = n / 2, i.e. threshold = sharesNum / 2

    val drng = new FieldElementSP800DRNG(ctx.group.createRandomNumber.toByteArray, ctx.group.groupOrder)
    val secret = drng.nextRand

    val poly = Polynomial(ctx.group, threshold - 1, secret)
    val evaluation_points = for(point <- 1 to n) yield point

    val shares = getShares(poly, evaluation_points)
//    val shares = Seq(Share(shares_.head.point, shares_.head.value + 1)) ++ shares_.tail
//    val shares = evaluation_points.map(Share(_, scala.util.Random.nextInt().abs))

    val restoredSecret = restoreSecret(ctx.group, shares, threshold)
    val restoredSecret2 = restoreSecret(ctx.group, shares, threshold + 1)

    secret.equals(restoredSecret) && (restoredSecret == restoredSecret2)
  }
}
