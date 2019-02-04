package treasury.crypto.core.primitives.dlog

import java.security.SecureRandom

import scala.util.Try

trait ECDiscreteLogGroup extends DiscreteLogGroup {

  val curveName: String

  /*
   * Constructs a ECGroupElement with the provided x and y. Returns Failure in case (x,y) doesn't represent valid point
   */
  def generateElement(x: BigInt, y: BigInt): Try[ECGroupElement]

  /**
    * @return the infinity point of this dlog group
    */
  def infinityPoint: ECGroupElement
}