package treasury.crypto.core.primitives.dlog

import treasury.crypto.core.serialization.BytesSerializable

/*
 * An interface for a group element of the discrete group
 */
trait GroupElement extends BytesSerializable {

  /**
    * checks if this element is the identity of the group
    */
  def isIdentity: Boolean

  def size: Int = bytes.length
}