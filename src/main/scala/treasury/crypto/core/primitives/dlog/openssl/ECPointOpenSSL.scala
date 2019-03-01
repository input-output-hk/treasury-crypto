package treasury.crypto.core.primitives.dlog.openssl

import treasury.crypto.core.primitives.dlog.ECGroupElement
import treasury.crypto.core.serialization.Serializer

case class ECPointOpenSSL(point: Array[Byte]) extends ECGroupElement {

  override def getX: BigInt = ???

  override def getY: BigInt = ???

  override def isInfinity: Boolean = ???

  override type M = this.type
  override def serializer: Serializer[ECPointOpenSSL.this.type] = ???
}
