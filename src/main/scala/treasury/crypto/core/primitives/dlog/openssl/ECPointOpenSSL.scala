package treasury.crypto.core.primitives.dlog.openssl

import treasury.crypto.core.primitives.dlog.ECGroupElement
import treasury.crypto.core.serialization.Serializer

case class ECPointOpenSSL(x: BigInt, y: BigInt, override val isInfinity: Boolean) extends ECGroupElement {

  override def getX: BigInt = x

  override def getY: BigInt = y

  override type M = this.type
  override def serializer: Serializer[ECPointOpenSSL.this.type] = ???
}
