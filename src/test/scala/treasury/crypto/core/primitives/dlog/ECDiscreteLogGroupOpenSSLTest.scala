package treasury.crypto.core.primitives.dlog

import java.math.BigInteger

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.primitives.dlog.openssl.ECDiscreteLogGroupOpenSSL.AvailableCurves.AvailableCurves
import treasury.crypto.core.primitives.dlog.openssl.{ECDiscreteLogGroupOpenSSL, ECPointOpenSSL}

class ECDiscreteLogGroupOpenSSLTest extends FunSuite with TableDrivenPropertyChecks {

  case class CurveInfo(name: AvailableCurves, groupGeneratorHex: String, groupOrderHex: String)

  val curves =
    Table(
      "curve",
      CurveInfo(ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256k1, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
      CurveInfo(ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256r1, "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    )

  test("All supported curves can be successfully created") {
    forAll(curves) { curve =>
      require(ECDiscreteLogGroupOpenSSL(curve.name).isSuccess)
    }
  }

  test("All supported curves should provide an infinity point") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val infinityPoint = group.infinityPoint.asInstanceOf[ECPointOpenSSL]
      require(infinityPoint.equals(group.groupIdentity))
      require(infinityPoint.isIdentity)
      require(infinityPoint.isInfinity)
      require(infinityPoint.isOnCurve)
    }
  }

  test("All supported curves should correctly generate random group elements") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val point = group.createRandomGroupElement.get.asInstanceOf[ECPointOpenSSL]

      require(point.isOnCurve)
    }
  }

  test("group generator and group order for the curve should be as specified in the NIST standard") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val generator_hex = group.groupGenerator.asInstanceOf[ECPointOpenSSL].getHexString().toUpperCase
      require(curve.groupGeneratorHex.equals(generator_hex))

      val groupOrder = group.groupOrder
      val groupOrderFromNist = BigInt(new BigInteger(curve.groupOrderHex, 16))
      require(groupOrder == groupOrderFromNist)
    }
  }

  test("exponentiation to 1 should yield the same base element") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val base = group.groupGenerator.asInstanceOf[ECPointOpenSSL]

      val res = group.exponentiate(base, BigInt(1)).get.asInstanceOf[ECPointOpenSSL]
      require(res == base)

      val res2 = group.exponentiate(base, 1 - group.groupOrder).get.asInstanceOf[ECPointOpenSSL]
      require(res2 == base)

      val res3 = group.exponentiate(base, 1 + group.groupOrder).get.asInstanceOf[ECPointOpenSSL]
      require(res3 == base)
    }
  }

  test("exponentiation should work correctly for exponent > 1") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val base = group.groupGenerator.asInstanceOf[ECPointOpenSSL]
      val res = group.exponentiate(base, BigInt(13456))

      require(res.isSuccess)
    }
  }

  test("multiplication with infinity point should yield the same point") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val base = group.groupGenerator.asInstanceOf[ECPointOpenSSL]
      val res = group.multiply(base, group.groupIdentity).get.asInstanceOf[ECPointOpenSSL]

      require(res == base)
    }
  }

  test("multiplication with inverted point should yield infinity point") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val base = group.groupGenerator.asInstanceOf[ECPointOpenSSL]
      val res = group.multiply(base, group.inverse(base).get).get

      require(res.isIdentity)
    }
  }

  test("dividing point to itself should yield infinity point") {
    forAll(curves) { curve =>
      val group = ECDiscreteLogGroupOpenSSL(curve.name).get
      val base = group.groupGenerator.asInstanceOf[ECPointOpenSSL]
      val res = group.divide(base, base).get

      require(res.isIdentity)
    }
  }
}
