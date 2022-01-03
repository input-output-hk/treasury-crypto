package io.iohk.protocol.common.math

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.math.BigIntPolynomial
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.datastructures.Share

import scala.annotation.tailrec

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
  // The same as the 'evaluate' method but coefficients of evaluated polynomial are in lifted representation, i.e.: g^coeff
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

  // Returns the interpolated (reconstructed) polynomial (coefficients)
  def interpolate(point_value_set: Seq[(BigInt, BigInt)])
                 (implicit group: DiscreteLogGroup): Polynomial = {
    val n = group.groupOrder

    def basicPoly(xj: BigInt, x_all: Seq[BigInt]): BigIntPolynomial = {
      val (nominator, denominator) =
        x_all.foldLeft((new BigIntPolynomial(Array(BigInt(1).bigInteger)), BigInt(1))){
          case ((nom, denom), xi) =>
            if(xi != xj)
            {
              val xi_minus_x = new BigIntPolynomial(Array(xi.bigInteger, BigInt(-1).mod(n).bigInteger))
              val xi_minus_xj = (xi - xj).mod(n)

              val nominator = nom.multPlain(xi_minus_x); nominator.mod(n.bigInteger)
              (nominator, (denom * xi_minus_xj).mod(n))
            } else {
              (nom, denom)
            }
      }
      nominator.mult(denominator.modInverse(n).bigInteger); nominator.mod(n.bigInteger)
      nominator
    }

    @tailrec
    def removeLeadingZeroes(coeffs: Seq[BigInt]): Seq[BigInt] = {
      if(coeffs.head == BigInt(0)) removeLeadingZeroes(coeffs.tail)
      else coeffs
    }

    val all_points = point_value_set.map(_._1)

    val coeffs =
      point_value_set.foldLeft(new BigIntPolynomial(Array(BigInt(0).bigInteger))){
        case(sum, (point, value)) =>
          val result = basicPoly(point, all_points)
          result.mult(value.bigInteger); result.mod(n.bigInteger)
          sum.add(result); sum.mod(n.bigInteger)
          sum
      }.getCoeffs.map(BigInt(_))

    // Removing the most significant zero-coefficients in case when the degree of interpolated polynomial is lesser
    //  then the number of specified point-values
    val coeffs_normalized = removeLeadingZeroes(coeffs.reverse).reverse
    Polynomial(group, coeffs_normalized.length - 1, coeffs_normalized.head, coeffs_normalized.tail)
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
