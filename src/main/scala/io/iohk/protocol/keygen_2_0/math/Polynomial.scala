package io.iohk.protocol.keygen_2_0.math

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG

/**
  * Represents polynomial of the form a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t, where t is the degree of the polynomial
  *
  * @param dlogGroup group of elements which provides DLP-based security
  * @param degree degree of the polynomial
  * @param a_0 free coefficient of the polynomial
  * @param coeffs all other coefficients a_1,..,a_t; Can be empty, then coefficients are generated with drng
  */
case class Polynomial(dlogGroup: DiscreteLogGroup, degree: Int, a_0: BigInt, coeffs: Seq[BigInt] = Seq()) {

  // Modulus that defines a Galois Field over which the polynomial is defined
  private val modulus = dlogGroup.groupOrder

  // Sequence of coefficients [a_0, a_1, a_2, ..., a_degree]
  val polynomial: Seq[BigInt] = {
    Seq(a_0) ++ {
      if(coeffs.isEmpty){
        val drng = new FieldElementSP800DRNG(dlogGroup.createRandomNumber.toByteArray, modulus)
        // Generating random coefficients a_1 to a_degree
        for(_ <- 0 until degree) yield drng.nextRand
      } else {
        // Setting provided coefficients [a_1, ..., a_degree]
        require(coeffs.length == degree, "Number of coefficients is inconsistent with the specified degree")
        coeffs
      }
    }
  }

  // Computing polynomial value for a specified x argument
  def evaluate(x: BigInt): BigInt = {
    polynomial.zipWithIndex.foldLeft(BigInt(0)){
      (sum, coeff_index) =>
        val (c, i) = coeff_index
        (sum + c * x.pow(i)) mod modulus
    }
  }

  // Evaluating polynomial in a specified point
  def evaluate(x: Int): BigInt = evaluate(BigInt(x))

  // Retrieving value of a coefficient by index
  def apply(i: Int): BigInt = polynomial(i)
}
