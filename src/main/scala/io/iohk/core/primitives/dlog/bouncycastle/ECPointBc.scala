package io.iohk.core.primitives.dlog.bouncycastle

import com.google.common.primitives.Bytes
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, ECGroupElement, GroupElement}
import io.iohk.core.serialization.Serializer
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, ECGroupElement, GroupElement}
import io.iohk.core.serialization.Serializer

import scala.util.Try

case class ECPointBc(point: ECPoint) extends ECGroupElement {

  override type M = ECPointBc
  override type DECODER = ECDiscreteLogGroupBc

  override val serializer = ECPointBcSerializer

  override def getX: BigInt = if (isInfinity) -1 else point.normalize.getXCoord.toBigInteger

  override def getY: BigInt = if (isInfinity) -1 else point.normalize.getYCoord.toBigInteger

  override def isInfinity: Boolean = point.isInfinity

  override def multiply(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupBc])
    dlog.multiply(this, that)
  }

  override def pow(exp: BigInt)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupBc])
    dlog.exponentiate(this, exp)
  }

  override def divide(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupBc])
    dlog.divide(this, that)
  }

  override def inverse()(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupBc])
    dlog.inverse(this)
  }

  override def toString: String = Hex.toHexString(point.getEncoded(true))
}

object ECPointBcSerializer extends Serializer[ECPointBc, ECDiscreteLogGroupBc] {

  override def toBytes(obj: ECPointBc): Array[Byte] = {
    obj.point.getEncoded(true)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[ECDiscreteLogGroupBc]): Try[ECPointBc] = Try {
    val group = decoder.get
    val point = group.curve.decodePoint(bytes)
    ECPointBc(point)
  }
}
