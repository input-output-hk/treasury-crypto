package io.iohk.protocol.common.math

import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

import scala.util.Random

class LagrangeInterpolationTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))

  import context.group
  test("interpolation"){
    val minimal_degree = 20
    val rand_range = 20 // 0 to 19 with Random.nextInt

    val degree = minimal_degree + Random.nextInt(rand_range)
    val polynomial = Polynomial(context.group, degree, context.group.createRandomNumber)

    val point_value =
      (1 to (degree + 1 + Random.nextInt(rand_range)))      // Random.nextInt is for redundant point-values
        .map(_ => group.createRandomNumber)                 // generating random points
        .map(point => (point, polynomial.evaluate(point)))  // evaluating polynomial in random points

    assert(LagrangeInterpolation.interpolate(point_value).coeffs() == polynomial.coeffs())
  }
}
