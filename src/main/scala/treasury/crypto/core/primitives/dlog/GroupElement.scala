package treasury.crypto.core.primitives.dlog

import treasury.crypto.core.serialization.BytesSerializable

import scala.util.Try

/*
 * An interface for a group element of the discrete multiplicative group
 */
trait GroupElement extends BytesSerializable with Ordered[GroupElement] {

  def isIdentity: Boolean

  def multiply(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement]

  def multiply(that: Try[GroupElement])(implicit dlog: DiscreteLogGroup): Try[GroupElement] = that.flatMap(this.multiply(_))

  def * (that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = this.multiply(that)

  def * (that: Try[GroupElement])(implicit dlog: DiscreteLogGroup): Try[GroupElement] = that.flatMap(this.multiply(_))

  def pow(exp: BigInt)(implicit dlog: DiscreteLogGroup): Try[GroupElement]

  def divide(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement]

  def divide(that: Try[GroupElement])(implicit dlog: DiscreteLogGroup): Try[GroupElement] = that.flatMap(this.divide(_))

  def / (that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = this.divide(that)

  def / (that: Try[GroupElement])(implicit dlog: DiscreteLogGroup): Try[GroupElement] = that.flatMap(this.divide(_))

  def inverse()(implicit dlog: DiscreteLogGroup): Try[GroupElement]

  def size: Int = bytes.length


  /**
    * Compares 2 group elements
    *
    * @param that a group element of the same type as this. Otherwise exception will be thrown
    * @return -1 if this < that, 0 if this == that and 1 if this > that
    */
  override def compare(that: GroupElement): Int
}