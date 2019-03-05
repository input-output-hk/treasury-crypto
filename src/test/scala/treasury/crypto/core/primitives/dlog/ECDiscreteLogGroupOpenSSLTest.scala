package treasury.crypto.core.primitives.dlog

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.primitives.dlog.openssl.{ECDiscreteLogGroupOpenSSL, ECPointOpenSSL}

class ECDiscreteLogGroupOpenSSLTest extends FunSuite with TableDrivenPropertyChecks {

  val curves =
    Table(
      "curve",
      ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256k1,
      ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256r1,
    )

  test("All supported curves can be successfully created") {
    forAll(curves) { curve =>
      require(ECDiscreteLogGroupOpenSSL(curve).isSuccess)
    }
  }

  test("All supported curves should provide an infinity point") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve).get
      val infinityPoint = group.infinityPoint.asInstanceOf[ECPointOpenSSL]
      require(infinityPoint.equals(group.groupIdentity))
      require(infinityPoint.isIdentity)
      require(infinityPoint.isInfinity)
      require(infinityPoint.isOnCurve)
    }
  }

  // TODO: enable it once everything is done
  ignore("All supported curves should correctly generate random group elements") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve).get
      val point = group.createRandomGroupElement.get.asInstanceOf[ECPointOpenSSL]

      require(point.isOnCurve)
    }
  }
}
