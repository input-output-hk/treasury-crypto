package treasury.crypto.core.primitives.dlog.openssl

import java.math.BigInteger
import java.security.InvalidAlgorithmParameterException
import java.security.spec.ECPoint

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import treasury.crypto.core.primitives.dlog.openssl.ECDiscreteLogGroupOpenSSL.AvailableCurves.AvailableCurves
import treasury.crypto.core.primitives.dlog.{ECDiscreteLogGroup, ECGroupElement, GroupElement}
import treasury.crypto.native.OpenSslAPI.{BN_CTX_PTR, BadPointerException, EC_GROUP_PTR, PointConversionForm}
import treasury.crypto.native.{NativeLibraryLoader, OpenSslAPI}

import scala.util.Try

class ECDiscreteLogGroupOpenSSL private (override val curveName: String,
                                         openSslApi: OpenSslAPI,
                                         bnCtx: BN_CTX_PTR,
                                         ecGroup: EC_GROUP_PTR) extends ECDiscreteLogGroup {

  override def generateElement(x: BigInt, y: BigInt): Try[ECGroupElement] = ???

  override lazy val infinityPoint: ECGroupElement = ECPointOpenSSL.getInfinityPoint(ecGroup, bnCtx, openSslApi)

  override lazy val groupGenerator: GroupElement = {
    val nativePoint = openSslApi.EC_GROUP_get0_generator(ecGroup)
    val point = ECPointOpenSSL(nativePoint, ecGroup, bnCtx, openSslApi).get
    point
  }

  override lazy val groupOrder: BigInt = {
    val bignum = openSslApi.EC_GROUP_get0_order(ecGroup)
    val buf = new Array[Byte](64)
    val len = openSslApi.BN_bn2bin(bignum, buf)
    require(len <= 64)
    BigInt(1, buf.take(len))
  }

  override def groupIdentity: GroupElement = infinityPoint

  override def exponentiate(base: GroupElement, exponent: BigInt): Try[GroupElement] = Try {
    val nativeBase = base.asInstanceOf[ECPointOpenSSL].generateNativePoint.get

    // We cannot use BN_bin2bn for negative numbers, so use the absolute value of exponent and then
    // make the BIGNUM negative if needed
    val exponentBytes = exponent.abs.toByteArray
    val nativeExponent = openSslApi.BN_bin2bn(exponentBytes, exponentBytes.length, null)
    if (nativeExponent == null || nativeExponent.address() == 0) {
      openSslApi.EC_POINT_free(nativeBase)
      throw new BadPointerException("Can not convert exponent to BigNum")
    }
    if (exponent < 0) {
      openSslApi.BN_set_negative(nativeExponent, 1)
      val nativeMod = openSslApi.BN_bin2bn(groupOrder.toByteArray, groupOrder.toByteArray.length, null)
      openSslApi.BN_nnmod(nativeExponent, nativeExponent, nativeMod, bnCtx)
      openSslApi.BN_free(nativeMod)
    }

    val res = openSslApi.EC_POINT_mul(ecGroup, nativeBase, null, nativeBase, nativeExponent, bnCtx)
    openSslApi.BN_free(nativeExponent)
    if (!res) {
      openSslApi.EC_POINT_free(nativeBase)
      throw new Exception("Error while exponentiating")
    }

    val result = ECPointOpenSSL(nativeBase, ecGroup, bnCtx, openSslApi).get
    openSslApi.EC_POINT_free(nativeBase)

    result
  }

  override def multiply(groupElement1: GroupElement, groupElement2: GroupElement): Try[GroupElement] = Try {
    val nativeElem1 = groupElement1.asInstanceOf[ECPointOpenSSL].generateNativePoint.get
    val nativeElem2Try = groupElement2.asInstanceOf[ECPointOpenSSL].generateNativePoint
    if (nativeElem2Try.isFailure) {
      openSslApi.EC_POINT_free(nativeElem1)
      throw new Exception("Can not generate native point")
    }
    val nativeElem2 = nativeElem2Try.get

    // store result in nativeElem1
    val res = openSslApi.EC_POINT_add(ecGroup, nativeElem1, nativeElem1, nativeElem2, bnCtx)
    openSslApi.EC_POINT_free(nativeElem2)
    if (!res) {
      openSslApi.EC_POINT_free(nativeElem1)
      throw new Exception("Can not add native points")
    }

    val groupElem = ECPointOpenSSL(nativeElem1, ecGroup, bnCtx, openSslApi).get
    openSslApi.EC_POINT_free(nativeElem1)

    groupElem
  }

  override def divide(groupElement1: GroupElement, groupElement2: GroupElement): Try[GroupElement] = {
    inverse(groupElement2).flatMap { inv =>
      multiply(groupElement1, inv)
    }
  }

  override def inverse(groupElement: GroupElement): Try[GroupElement] = Try {
    val nativeElem = groupElement.asInstanceOf[ECPointOpenSSL].generateNativePoint.get
    val res = openSslApi.EC_POINT_invert(ecGroup, nativeElem, bnCtx)
    if (!res) {
      openSslApi.EC_POINT_free(nativeElem)
      throw new Exception("Can not invert point")
    }

    val groupElem = ECPointOpenSSL(nativeElem, ecGroup, bnCtx, openSslApi).get
    openSslApi.EC_POINT_free(nativeElem)

    groupElem
  }

  override def reconstructGroupElement(bytes: Array[Byte]): Try[GroupElement] = ???

  override def finalize(): Unit = {
    openSslApi.BN_free(bnCtx)
    openSslApi.EC_GROUP_free(ecGroup)

    super.finalize()
  }
}

object ECDiscreteLogGroupOpenSSL {

  object AvailableCurves extends Enumeration {
    type AvailableCurves = String
    val secp256k1 = "secp256k1"
    val secp256r1 = "secp256r1"
  }

  def apply(curve: AvailableCurves): Try[ECDiscreteLogGroupOpenSSL] = Try {
    val openSslApi = NativeLibraryLoader.openSslAPI.get
    curve match {
      case AvailableCurves.secp256k1 => { // this one is not defined in the OpenSSL so use the spec from BouncyCastle
        val bnCtx = openSslApi.BN_CTX_new
        val ecGroup = createECGroupFromSpec(ECNamedCurveTable.getParameterSpec(AvailableCurves.secp256k1), openSslApi, bnCtx).get
        new ECDiscreteLogGroupOpenSSL(AvailableCurves.secp256k1, openSslApi, bnCtx, ecGroup)
      }
      case AvailableCurves.secp256r1 => { // it is defined in the OpenSSL by name "P-256"
        val bnCtx = openSslApi.BN_CTX_new
        val ecGroup = createECGroup("P-256", openSslApi, bnCtx).get
        new ECDiscreteLogGroupOpenSSL(AvailableCurves.secp256r1, openSslApi, bnCtx, ecGroup)
      }
      case _ => throw new IllegalArgumentException(s"Curve $curve is not supported")
    }
  }

  /* Creates an elliptic curve group based on the provided ECParameterSpec. In may be useful if needed to use a curve
  *  that is not defined in the OpenSSL library.
  */
  private def createECGroupFromSpec(ecSpec: ECParameterSpec, openSslApi: OpenSslAPI, bnCtxIn: BN_CTX_PTR): Try[EC_GROUP_PTR] = Try {
    val a = ecSpec.getCurve.getA.toBigInteger.toByteArray
    val b = ecSpec.getCurve.getB.toBigInteger.toByteArray
    val p = ecSpec.getCurve.getField.getCharacteristic.toByteArray

    val a_ptr = openSslApi.BN_bin2bn(a, a.length, null)
    val b_ptr = openSslApi.BN_bin2bn(b, b.length, null)
    val p_ptr = openSslApi.BN_bin2bn(p, p.length, null)

    val ec_group = openSslApi.EC_GROUP_new_curve_GFp(p_ptr, a_ptr, b_ptr, bnCtxIn)

    openSslApi.BN_free(a_ptr)
    openSslApi.BN_free(b_ptr)
    openSslApi.BN_free(p_ptr)

    if (ec_group == null || ec_group.address() == 0)
      throw new InvalidAlgorithmParameterException("Can not create curve")

    val G = ecSpec.getG.getEncoded(true) // group generator
    val G_bignum = openSslApi.BN_bin2bn(G, G.length, null)

    val G_point = openSslApi.EC_POINT_bn2point(ec_group, G_bignum, null, bnCtxIn)
    openSslApi.BN_free(G_bignum)
    if (!openSslApi.EC_POINT_is_on_curve(ec_group, G_point, bnCtxIn)) {
      openSslApi.EC_POINT_free(G_point)
      openSslApi.EC_GROUP_free(ec_group)
      throw new InvalidAlgorithmParameterException("Provided base point is not on the curve")
    }

    val orderOfG = ecSpec.getN.toByteArray
    val cofactor = ecSpec.getH.toByteArray
    val orderOfG_bignum = openSslApi.BN_bin2bn(orderOfG, orderOfG.length, null)
    val cofactor_bignum = openSslApi.BN_bin2bn(cofactor, cofactor.length, null)

    val gen_check = openSslApi.EC_GROUP_set_generator(ec_group, G_point, orderOfG_bignum, cofactor_bignum)
    openSslApi.BN_free(orderOfG_bignum)
    openSslApi.BN_free(cofactor_bignum)
    openSslApi.EC_POINT_free(G_point)
    if (!gen_check) {
      openSslApi.EC_GROUP_free(ec_group)
      throw new InvalidAlgorithmParameterException("Can not set generator for the curve")
    }

    if (!openSslApi.EC_GROUP_check(ec_group, bnCtxIn)) {
      openSslApi.EC_GROUP_free(ec_group)
      throw new InvalidAlgorithmParameterException("Curve can not be created")
    }

    ec_group
  }

  /* Creates an elliptic curve group by using one of the predefined OpenSSL curves.
  */
  private def createECGroup(openSSLcurveName: String, openSslApi: OpenSslAPI, bnCtx: BN_CTX_PTR): Try[EC_GROUP_PTR] = Try {
    val nid = openSslApi.EC_curve_nist2nid(openSSLcurveName)
    val ec_group = openSslApi.EC_GROUP_new_by_curve_name(nid)

    if (!openSslApi.EC_GROUP_check(ec_group, bnCtx)) {
      openSslApi.EC_GROUP_free(ec_group)
      throw new IllegalArgumentException(s"Can not create curve: $openSSLcurveName")
    }

    ec_group
  }
}