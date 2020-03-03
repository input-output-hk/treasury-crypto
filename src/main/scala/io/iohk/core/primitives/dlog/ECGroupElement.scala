package io.iohk.core.primitives.dlog

/*
 * An interface for a group element of the elliptic curve discrete group
 */
trait ECGroupElement extends GroupElement {

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

  override def isIdentity: Boolean = isInfinity

  override def compare(that: GroupElement): Int = {
    require(that.isInstanceOf[ECGroupElement])
    val e = that.asInstanceOf[ECGroupElement]

    val x1 = this.getX
    val x2 = e.getX
    x1.compareTo(x2) match {
      case 0 => {
        val y1 = this.getY
        val y2 = e.getY
        y1.compareTo(y2)
      }
      case x => x
    }
  }
}
