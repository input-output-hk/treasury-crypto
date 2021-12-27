package io.iohk.protocol.common.him

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.common.math.LagrangeInterpolation

import scala.util.Try

case class HIM(alpha_points: Seq[BigInt],
               beta_points: Seq[BigInt])
              (implicit group: DiscreteLogGroup){
  // Multiplies HIM by a given sequence of values, treated as a column
  // Outputs a new column of output values
  // Input and output values are the evaluations of the same polynomial in points alpha (for input) and beta (for output)
  def mul(input: Seq[BigInt]): Seq[BigInt] = {
    assert(input.length == alpha_points.length)
    beta_points.map(LagrangeInterpolation.evaluate(alpha_points.zip(input), _))
  }

  // The same as mul, but the input and output values are in lifted representation, i.e.: g^value
  def mulLifted(input: Seq[GroupElement]): Seq[GroupElement] = {
    assert(input.length == alpha_points.length)
    beta_points.map(LagrangeInterpolation.evaluateLifted(alpha_points.zip(input), _))
  }
}

object HIM {
  def testHIM(n: Int, m: Int)
             (implicit group: DiscreteLogGroup): Try[Unit] = Try{
    val alphas = (1 to n).map(_ => group.createRandomNumber)
    val betas  = (1 to m).map(_ => group.createRandomNumber)
    val him = HIM(alphas, betas)

    val input = (1 to alphas.length).map(_ => group.createRandomNumber)
    val output = him.mul(input)

    // Checking that polynomials defined by (alphas, input) and (betas, output) are the same by evaluating both of them in random points
    (1 to n + m).map(_ => group.createRandomNumber).foreach{
      point =>
        assert(
          LagrangeInterpolation.evaluate(alphas.zip(input), point) ==
            LagrangeInterpolation.evaluate(betas.zip(output), point)
        )
    }

    val inputLifted = (1 to alphas.length).map(_ => group.createRandomGroupElement.get)
    val outputLifted = him.mulLifted(inputLifted)

    // Checking that lifted polynomials defined by (alphas, inputLifted) and (betas, outputLifted) are the same by evaluating both of them in random points
    (1 to n + m).map(_ => group.createRandomNumber).foreach{
      point =>
        assert(
          LagrangeInterpolation.evaluateLifted(alphas.zip(inputLifted), point) ==
            LagrangeInterpolation.evaluateLifted(betas.zip(outputLifted), point)
        )
    }
  }
}