package io.iohk.protocol.common.utils

import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.utils.DlogGroupArithmetics.evaluateLiftedPoly
import org.scalatest.FunSuite

import scala.util.Random

class DlogGroupArithmeticsTests  extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val g = context.group.groupGenerator

  import context.group
  test("evaluateLiftedPoly"){
    val degree = Random.nextInt(20) + 20

    val polynomial = Polynomial(context.group, degree, context.group.createRandomNumber)
    val liftedCoeffs = polynomial.coeffs().map(c => g.pow(c).get)
    val evalPoint = group.createRandomNumber

    assert(evaluateLiftedPoly(liftedCoeffs, evalPoint) == g.pow(polynomial.evaluate(evalPoint)).get)
  }
}
