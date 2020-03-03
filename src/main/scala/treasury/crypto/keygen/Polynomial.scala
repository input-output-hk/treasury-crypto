package treasury.crypto.keygen

import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.primitives.numbergenerator.FieldElementSP800DRNG

class Polynomial(cs: Cryptosystem, a_0: BigInt, degree: Int) {

  private val polynomial = new Array[BigInt](degree)

  val drng = new FieldElementSP800DRNG(a_0.toByteArray, cs.orderOfBasePoint)

  // Generating random polynomial coefficients
  for(i <- polynomial.indices) {
    if (i == 0)
      polynomial(0) = a_0
    else
      polynomial(i) = drng.nextRand
  }

  // Computing the polynomial value for specified x argument
  def evaluate(x: BigInt): BigInt = {
    var res = polynomial(0)
    for(i <- 1 until polynomial.length)
      res = (polynomial(i) * x.pow(i) + res) mod cs.orderOfBasePoint
    res
  }

  def evaluate(x: Int): BigInt = evaluate(BigInt(x))

  // Retrieving the value of coefficient by index
  def apply(i: Int): BigInt = polynomial(i)
}
