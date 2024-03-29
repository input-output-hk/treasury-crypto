package io.iohk.core.crypto.primitives.dlog

import io.iohk.core.crypto.primitives.dlog.GroupParameters.EllipticCurveParameters
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

class ECGroupElementTest extends FunSuite with TableDrivenPropertyChecks {

  import ECDiscreteLogGroupTest.ellipticCurveGroups

  test("any group element should support extracting X and Y coordinates") {
    forAll(ellipticCurveGroups) { case (groupType, group) =>
      val e1 = group.createRandomGroupElement.get.asInstanceOf[ECGroupElement]
      val X = e1.getX
      val Y = e1.getY

      require(X > 0 && Y > 0)
    }
  }

  test("X and Y coordinates of the point at infinity should be -1") {
    forAll(ellipticCurveGroups) { case (groupType, group) =>
      val X = group.infinityPoint.getX
      val Y = group.infinityPoint.getY

      require(X == -1 && Y == -1)
    }
  }

  test("X and Y coordinates of the group generator should conform to the specification") {
    forAll(ellipticCurveGroups) { case (groupType, group) =>
      val params = GroupParameters.getGroupParameters(groupType).asInstanceOf[EllipticCurveParameters]
      val groupGenerator = group.groupGenerator.asInstanceOf[ECGroupElement]

      require(groupGenerator.getX == BigInt(params.generatorX, 16))
      require(groupGenerator.getY == BigInt(params.generatorY, 16))
    }
  }
}
