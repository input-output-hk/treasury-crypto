package io.iohk.protocol.keygen_2_0.math

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext

import scala.collection.mutable.ArrayBuffer

/**
  * Represents polynomial of the form a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t, where t is the degree of the polynomial
  *
  * @param dlogGroup group of elements with DLP-based security
  * @param degree degree of the polynomial
  * @param a_0 free coefficient of the polynomial
  * @param coeffs all other coefficients a_1,..,a_t; Can be empty, then they are generated with drng
  */
case class Polynomial(dlogGroup: DiscreteLogGroup, degree: Int, a_0: BigInt, coeffs: Seq[BigInt] = Seq()) {

  private val modulus = dlogGroup.groupOrder

  // Sequence of coefficients [a_0, a_1, a_2, ..., a_degree]
  private val polynomial = {
    Seq(a_0) ++ {
      if(coeffs.isEmpty){
        val drng = new FieldElementSP800DRNG(dlogGroup.createRandomNumber.toByteArray, modulus)
        // Generating random coefficients a_1 to a_degree
        for(_ <- 0 until degree) yield drng.nextRand
      } else {
        // Setting provided coefficients a_1 to a_degree
        require(coeffs.length == degree, "Number of coefficients is inconsistent with specified degree")
        coeffs
      }
    }
  }

  // Computing the polynomial value for specified x argument
  def evaluate(x: BigInt): BigInt = {
    polynomial.zipWithIndex.foldLeft(BigInt(0)){
      (sum, coeff_index) =>
        val (c, i) = coeff_index
        (sum + c * x.pow(i)) mod modulus
    }
  }

  def evaluate(x: Int): BigInt = evaluate(BigInt(x))

  // Retrieving the value of coefficient by index
  def apply(i: Int): BigInt = polynomial(i)
}
