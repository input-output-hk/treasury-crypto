package treasury.crypto.core.primitives.dlog

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.dlog.openssl.ECDiscreteLogGroupOpenSSL

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
}
