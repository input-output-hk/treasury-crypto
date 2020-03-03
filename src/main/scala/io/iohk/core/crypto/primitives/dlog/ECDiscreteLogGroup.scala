package io.iohk.core.crypto.primitives.dlog

import scala.util.Try

trait ECDiscreteLogGroup extends DiscreteLogGroup {

  def curveName: String

  /*
   * Constructs a ECGroupElement with the provided x and y. Returns Failure in case (x,y) doesn't represent valid point
   */
  def generateElement(x: BigInt, y: BigInt): Try[ECGroupElement]

  /**
    * @return the infinity point of this dlog group
    */
  def infinityPoint: ECGroupElement

  /**
    * @return free constant A - parameter of the curve y^2 = x^3 + Ax + B
    */
  def getA: BigInt

  /**
    * @return free constant B - parameter of the curve y^2 = x^3 + Ax + B
    */
  def getB: BigInt

  /**
    * @return characteristic of the field over which elliptic curve is built
    */
  def getFieldCharacteristic: BigInt
}
