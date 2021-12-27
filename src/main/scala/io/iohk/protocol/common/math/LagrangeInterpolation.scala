package io.iohk.protocol.common.math

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.datastructures.Share

object LagrangeInterpolation {

  def getLagrangeCoeff(x: BigInt, x_all: Seq[BigInt], eval_point: BigInt)
                      (implicit group: DiscreteLogGroup) : BigInt = {
    val n = group.groupOrder

    x_all.foldLeft(BigInt(1)){
      (lambda, x_i) =>
        if(x_i != x)
        {
          val J_minus_EP = (x_i - eval_point).mod(n)
          val J_minus_I = (x_i - x).mod(n)

          (lambda * (J_minus_EP * J_minus_I.modInverse(n)).mod(n)).mod(n)
        } else {
          lambda
        }
    }
  }

  def getLagrangeCoeff(implicit group: DiscreteLogGroup, x: Int, x_all: Seq[Int], eval_point: Int = 0): BigInt = {
    getLagrangeCoeff(BigInt(x.toLong), x_all.map(x_i => BigInt(x_i.toLong)), BigInt(eval_point.toLong))
  }

  // Evaluates interpolated polynomial (by a point-value's set of in the 'point_value_set') in a point specified with 'eval_point'
  def evaluate(point_value_set: Seq[(BigInt, BigInt)], eval_point: BigInt)
              (implicit group: DiscreteLogGroup): BigInt = {
    val all_points = point_value_set.map(_._1)

    point_value_set.foldLeft(BigInt(0)){
      case(sum, (point, value)) =>
        (LagrangeInterpolation.getLagrangeCoeff(
          point,
          all_points,
          eval_point
        ) * value + sum).mod(group.groupOrder)
    }
  }

  def evaluateLifted(point_liftedValue_set: Seq[(BigInt, GroupElement)], eval_point: BigInt)
                    (implicit group: DiscreteLogGroup): GroupElement = {
    val all_points = point_liftedValue_set.map(_._1)

    point_liftedValue_set.foldLeft(group.groupIdentity){
      case(product, (point, liftedValue)) =>
        val lambda = LagrangeInterpolation.getLagrangeCoeff(
          point,
          all_points,
          eval_point
        )
        liftedValue.pow(lambda).get.multiply(product).get
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
