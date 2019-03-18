package treasury.crypto.core.encryption.elgamal

import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, GroupElement}

import scala.util.Try

/*
 * Represents a ciphertext for the ElGamal assymetric cryptosystem.
 * It also supports a couple of methods that facilitate homomorphic transformations of a ciphertext
 */
case class ElGamalCiphertext(c1: GroupElement, c2: GroupElement) {

  def pow(exp: BigInt)(implicit dlog: DiscreteLogGroup): Try[ElGamalCiphertext] = Try {
    ElGamalCiphertext(c1.pow(exp).get, c2.pow(exp).get)
  }

  def multiply(that: ElGamalCiphertext)(implicit dlog: DiscreteLogGroup): Try[ElGamalCiphertext] = Try {
    ElGamalCiphertext(c1.multiply(that.c1).get, c2.multiply(that.c2).get)
  }

  @throws[Exception]("if underlying multiply failed")
  def * (that: ElGamalCiphertext)(implicit dlog: DiscreteLogGroup): ElGamalCiphertext = this.multiply(that).get
}
