package treasury.crypto.core.primitives.dlog.openssl

import java.security.InvalidAlgorithmParameterException

import jnr.ffi.Pointer
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import treasury.crypto.core.primitives.dlog.bouncycastle.ECDiscreteLogGroupBc
import treasury.crypto.core.primitives.dlog.{ECDiscreteLogGroup, ECGroupElement, GroupElement}
import treasury.crypto.native.OpenSslAPI.{BN_CTX_PTR, EC_GROUP_PTR}
import treasury.crypto.native.{NativeLibraryLoader, OpenSslAPI}

import scala.util.Try

class ECDiscreteLogGroupOpenSSL private(curveNameIn: String, ecSpecIn: ECParameterSpec, openSslApiIn: OpenSslAPI)
  extends ECDiscreteLogGroup {

  private val curveSpec = ecSpecIn
  private val openSslApi = openSslApiIn

  private val bnCtx: Pointer = openSslApi.BN_CTX_new
  private val curve: Pointer = createCurve(ecSpecIn, bnCtx).get
  private val curve2: Pointer = createCurve2("P-256", bnCtx).get

  override val curveName: String = curveNameIn

  private def createCurve(ecSpec: ECParameterSpec, bnCtxIn: BN_CTX_PTR): Try[EC_GROUP_PTR] = Try {
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

    val G = ecSpec.getG.getEncoded(true) // group generator
    val G_bignum = openSslApi.BN_bin2bn(G, G.length, null)

    val G_point = openSslApi.EC_POINT_bn2point(ec_group, G_bignum, null, bnCtxIn)
    openSslApi.BN_free(G_bignum)
    if (!openSslApi.EC_POINT_is_on_curve(ec_group, G_point, bnCtxIn)) {
      openSslApi.BN_free(G_point)
      openSslApi.BN_free(ec_group)
      throw new InvalidAlgorithmParameterException("Provided base point is not on the curve")
    }

    val orderOfG = ecSpec.getN.toByteArray
    val cofactor = ecSpec.getH.toByteArray
    val orderOfG_bignum = openSslApi.BN_bin2bn(orderOfG, orderOfG.length, null)
    val cofactor_bignum = openSslApi.BN_bin2bn(cofactor, cofactor.length, null)

    val gen_check = openSslApi.EC_GROUP_set_generator(ec_group, G_point, orderOfG_bignum, cofactor_bignum)
    openSslApi.BN_free(orderOfG_bignum)
    openSslApi.BN_free(cofactor_bignum)
    openSslApi.BN_free(G_point)
    if (!gen_check) {
      openSslApi.BN_free(ec_group)
      throw new InvalidAlgorithmParameterException("Can not set generator for the curve")
    }

    if (!openSslApi.EC_GROUP_check(ec_group, bnCtxIn)) {
      openSslApi.BN_free(ec_group)
      throw new InvalidAlgorithmParameterException("Curve can not be created")
    }

    ec_group
  }

  private def createCurve2(openSSLcurveName: String, bnCtxIn: BN_CTX_PTR): Try[EC_GROUP_PTR] = Try {
    val nid = openSslApi.EC_curve_nist2nid(openSSLcurveName)
    val ec_group = openSslApi.EC_GROUP_new_by_curve_name(nid)

    if (!openSslApi.EC_GROUP_check(ec_group, bnCtxIn)) {
      openSslApi.BN_free(ec_group)
      throw new IllegalArgumentException(s"Can not create curve: $openSSLcurveName")
    }

    ec_group
  }

  override def generateElement(x: BigInt, y: BigInt): Try[ECGroupElement] = ???

  override def infinityPoint: ECGroupElement = ???

  override def groupGenerator: GroupElement = ???

  override def groupOrder: BigInt = ???

  override def groupIdentity: GroupElement = ???

  override def exponentiate(base: GroupElement, exponent: BigInt): Try[GroupElement] = ???

  override def multiply(groupElement1: GroupElement, groupElement2: GroupElement): Try[GroupElement] = ???

  override def divide(groupElement1: GroupElement, groupElement2: GroupElement): Try[GroupElement] = ???

  override def inverse(groupElement: GroupElement): Try[GroupElement] = ???

  override def reconstructGroupElement(bytes: Array[Byte]): Try[GroupElement] = ???

  override def finalize(): Unit = {
    openSslApi.BN_free(bnCtx)
    openSslApi.BN_free(curve)

    super.finalize()
  }
}

object ECDiscreteLogGroupOpenSSL {

  def apply(curveName: String): Try[ECDiscreteLogGroupOpenSSL] = Try {
    curveName match {
      case "secp256k1" => new ECDiscreteLogGroupOpenSSL(curveName, ECNamedCurveTable.getParameterSpec(curveName), NativeLibraryLoader.openSslAPI.get)
      case _ => throw new IllegalArgumentException(s"Curve $curveName is not supported")
    }
  }
}