package treasury.crypto.core.primitives.dlog

import java.math.BigInteger
import java.security.SecureRandom

import org.bouncycastle.util.BigIntegers

import scala.util.Try

/*
 * DiscreteLogGroup is an abstract class that implements common functionality for all discrete log groups
 */
trait DiscreteLogGroup {

  protected val random: SecureRandom = new SecureRandom()

  /**
    * The generator g of the group is an element that can be used to produce all other elements of the group by
    * exponentiating g sequentially.
    */
  def groupGenerator: GroupElement

  /**
    * @return the order of this Dlog group
    */
  def groupOrder: BigInt

  /**
    * @return the identity of this Dlog group (e.g. 1 for multiplicative group)
    */
  def groupIdentity: GroupElement

  /**
    * Raises the base GroupElement to the exponent. The result is another GroupElement.
    */
  def exponentiate(base: GroupElement, exponent: BigInt): Try[GroupElement]

  /**
    * Multiplies two GroupElements
    */
  def multiply(groupElement1: GroupElement, groupElement2: GroupElement): Try[GroupElement]

  /**
    * Divides two GroupElements
    */
  def divide(groupElement1: GroupElement, groupElement2: GroupElement): Try[GroupElement]

  /**
    * Inverts GroupElement
    */
  def inverse(groupElement: GroupElement): Try[GroupElement]

  /**
    * Creates a random element of this Dlog group
    */
  def createRandomGroupElement: Try[GroupElement] = {
    val rand = createRandomNumber
    exponentiate(groupGenerator, rand)
  }

  /*
  * Creates a positive random number in range [1,..,groupOrder -1]
  */
  def createRandomNumber: BigInt = {
    val qMinusOne = groupOrder - 1
    BigIntegers.createRandomInRange(BigInteger.ONE, qMinusOne.bigInteger, random)
  }

  /**
    * Reconstructs a GroupElement from bytes
    * @param bytes serialized GroupElement
    */
  def reconstructGroupElement(bytes: Array[Byte]): Try[GroupElement]
}
