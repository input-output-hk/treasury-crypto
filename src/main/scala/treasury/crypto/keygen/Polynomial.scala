package treasury.crypto.keygen

import java.math.BigInteger
import treasury.crypto.core.Cryptosystem

class Polynomial(cs: Cryptosystem, a_0: BigInteger, degree: Integer)
{
  private val polynomial = new Array[BigInteger](degree)

  // Generating random polynomial coefficients
  for(i <- polynomial.indices)
  {
    if(i == 0)
      polynomial(0) = a_0
    else
      polynomial(i) = cs.getRand
  }

  // Computing the polynomial value for specified x argument
  def apply(x: BigInteger): BigInteger =
  {
    var res = polynomial(0)
    for(i <- 1 until polynomial.length)
      res = polynomial(i).multiply(x.pow(i)).add(res).mod(cs.orderOfBasePoint)
    res
  }

  // Retrieving the value of coefficient by index
  def apply(i: Integer): BigInteger =
  {
    polynomial(i)
  }
}