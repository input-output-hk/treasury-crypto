package treasury.crypto.core.primitives.dlog.bouncycastle

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import treasury.crypto.core.primitives.dlog.{ECDiscreteLogGroup, ECGroupElement, GroupElement}

import scala.util.Try

class ECDiscreteLogGroupBc private (curveNameIn: String, ecSpecIn: ECParameterSpec) extends ECDiscreteLogGroup {

  private val curveSpec = ecSpecIn
  private val curve = ecSpecIn.getCurve

  override val curveName: String = curveNameIn

  override val groupGenerator: ECPointBc = ECPointBc(curveSpec.getG)

  override val groupOrder: BigInt = curve.getOrder

  override val groupIdentity: ECPointBc = ECPointBc(curve.getInfinity)

  override def infinityPoint: ECGroupElement = groupIdentity

  override def exponentiate(base: GroupElement, exponent: BigInt): Try[GroupElement] = Try {
    val point = base.asInstanceOf[ECPointBc].point
    val result = point.multiply(exponent.bigInteger)
    ECPointBc(result)
  }

  override def multiply(groupElement1: GroupElement, groupElement2: GroupElement): Try[GroupElement] = Try {
    val point1 = groupElement1.asInstanceOf[ECPointBc].point
    val point2 = groupElement2.asInstanceOf[ECPointBc].point
    val result = point1.add(point2)
    ECPointBc(result)
  }

  override def reconstructGroupElement(bytes: Array[Byte]): Try[GroupElement] = ???

  override def generateElement(x: BigInt, y: BigInt): Try[ECGroupElement] = ???
}

object ECDiscreteLogGroupBc {

  def apply(curveName: String): Try[ECDiscreteLogGroupBc] = Try {
    curveName match {
      case "secp256k1" => new ECDiscreteLogGroupBc(curveName, ECNamedCurveTable.getParameterSpec(curveName))
      case _ => throw new IllegalArgumentException(s"Curve $curveName is not supported")
    }
  }
}