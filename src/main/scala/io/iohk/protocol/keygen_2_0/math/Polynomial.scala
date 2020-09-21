package io.iohk.protocol.keygen_2_0.math

import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext

/**
  * Represents polynomial of the form a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t, where t is the degree of the polynomial
  *
  * @param ctx Cryptocontext
  * @param degree degree of the polynomial
  * @param a_0 free coefficient of the polynomial
  * @param drng random number generator that is used to generate all other coefficients a_1,..,a_t
  */
class Polynomial(ctx: CryptoContext, degree: Int, a_0: BigInt, drng: FieldElementSP800DRNG) {

  private val polynomial = new Array[BigInt](degree + 1) // array for coefficients

  polynomial(0) = a_0
  for(i <- 1 until polynomial.length)
      polynomial(i) = drng.nextRand   // Generating random coefficients

  // Computing the polynomial value for specified x argument
  def evaluate(x: BigInt): BigInt = {
    var res = polynomial(0)
    for(i <- 1 until polynomial.length)
      res = (polynomial(i) * x.pow(i) + res) mod ctx.group.groupOrder
    res
  }

  def evaluate(x: Int): BigInt = evaluate(BigInt(x))

  // Retrieving the value of coefficient by index
  def apply(i: Int): BigInt = polynomial(i)
}
