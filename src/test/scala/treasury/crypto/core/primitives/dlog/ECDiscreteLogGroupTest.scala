package treasury.crypto.core.primitives.dlog

import java.math.BigInteger

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.primitives.dlog.GroupParameters.EllipticCurveParameters

class ECDiscreteLogGroupTest extends FunSuite with TableDrivenPropertyChecks {

  import ECDiscreteLogGroupTest.ellipticCurveGroups

  test("verify that group params corresponds to the specification") {
    forAll(ellipticCurveGroups) { case (groupType, group) =>
      val params = GroupParameters.getGroupParameters(groupType).asInstanceOf[EllipticCurveParameters]
      require(group.groupGenerator.toString.toLowerCase == params.generator.toLowerCase)
      require(group.groupOrder == BigInt(new BigInteger(params.order, 16)))
      require(group.getA == BigInt(new BigInteger(params.A, 16)))
      require(group.getB == BigInt(new BigInteger(params.B, 16)))
      require(group.getFieldCharacteristic == BigInt(new BigInteger(params.fieldCharacteristic, 16)))

    }
  }

  test("All supported curves should provide an infinity point") {
    forAll(ellipticCurveGroups) { case (groupType, group) =>
      val ecGroup = group.asInstanceOf[ECDiscreteLogGroup]
      val infinityPoint = ecGroup.infinityPoint
      require(infinityPoint == group.groupIdentity)
      require(infinityPoint.isIdentity)
      require(infinityPoint.isInfinity)
      require(ecGroup.isValidGroupElement(infinityPoint))
    }
  }

  test("multiplication with infinity point should yield the same point") {
    forAll(ellipticCurveGroups) { case (groupType, group) =>
      val ecGroup = group.asInstanceOf[ECDiscreteLogGroup]
      val generator = ecGroup.groupGenerator.asInstanceOf[ECGroupElement]
      val res = ecGroup.multiply(generator, ecGroup.infinityPoint).get

      require(res.isInstanceOf[ECGroupElement])
      require(res == generator)
    }
  }
}

object ECDiscreteLogGroupTest extends TableDrivenPropertyChecks {

  val availableECGroups = DiscreteLogGroupFactory.AvailableGroups.getEllipticCurveGroups

  val ellipticCurveGroups =
    Table(
      "curve",
      availableECGroups.map(g => (g, DiscreteLogGroupFactory.constructDlogGroup(g).get.asInstanceOf[ECDiscreteLogGroup])):_*
    )
}
