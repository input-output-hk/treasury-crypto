package treasury.crypto.core.primitives.dlog

/*
 * An interface for a group element of the elliptic curve discrete group
 */
trait ECGroupElement extends GroupElement {

  override type M = ECGroupElement

  /**
    * Returns the x coordinate of the point on the given elliptic curve.
    * @return -1 in case of a point at infinity
    */
  def getX: BigInt

  /**
    * Returns the y coordinate of the point on the given elliptic curve.
    * @return -1 in case of a point at infinity
    */
  def getY: BigInt

  /**
    * Elliptic curve has a unique point called infinity.
    * This function returns true if this point is a point at infinity.
    */
  def isInfinity: Boolean
}
