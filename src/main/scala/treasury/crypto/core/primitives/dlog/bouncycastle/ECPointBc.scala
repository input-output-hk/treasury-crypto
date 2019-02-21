package treasury.crypto.core.primitives.dlog.bouncycastle

import com.google.common.primitives.Bytes
import org.bouncycastle.math.ec.ECPoint
import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.primitives.dlog.ECGroupElement
import treasury.crypto.core.serialization.Serializer

import scala.util.Try

case class ECPointBc(point: ECPoint) extends ECGroupElement {

  override type M = ECPointBc

  override def getX: BigInt = if (isInfinity) -1 else point.normalize.getXCoord.toBigInteger

  override def getY: BigInt = if (isInfinity) -1 else point.normalize.getYCoord.toBigInteger

  override def isInfinity: Boolean = point.isInfinity

  override val serializer = ECPointBcSerializer
}

object ECPointBcSerializer extends Serializer[ECPointBc] {

  override def toBytes(obj: ECPointBc): Array[Byte] = {
    val bytes = obj.point.getEncoded(true)
    Bytes.concat(Array(bytes.length.toByte), bytes)
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[ECPointBc] = Try {
    ???
  }
}
