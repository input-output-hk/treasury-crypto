package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core.{Cryptosystem, DRNG}

class Polynomial(cs: Cryptosystem, a_0: BigInteger, degree: Int) {

  private val polynomial = new Array[BigInteger](degree)

  val drng = DRNG(a_0.toByteArray, cs)

  // Generating random polynomial coefficients
  for(i <- polynomial.indices) {
    if (i == 0)
      polynomial(0) = a_0
    else
      polynomial(i) = drng.getRand
  }

  // Computing the polynomial value for specified x argument
  def evaluate(x: BigInteger): BigInteger = {
    var res = polynomial(0)
    for(i <- 1 until polynomial.length)
      res = polynomial(i).multiply(x.pow(i)).add(res).mod(cs.orderOfBasePoint)
    res
  }

  def evaluate(x: Int): BigInteger = evaluate(BigInteger.valueOf(x))

  // Retrieving the value of coefficient by index
  def apply(i: Int): BigInteger = polynomial(i)
}
