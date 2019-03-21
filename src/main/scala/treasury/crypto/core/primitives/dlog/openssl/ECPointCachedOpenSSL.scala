package treasury.crypto.core.primitives.dlog.openssl

import java.util

import treasury.crypto.core.serialization.Serializer
import treasury.crypto.native.OpenSslAPI
import treasury.crypto.native.OpenSslAPI.PointConversionForm.PointConversionForm
import treasury.crypto.native.OpenSslAPI._

import scala.util.Try

/**
  * This class represents a point on the curve. Note that it holds a reference to the native EC_POINT object which is
  * freed in the finalize method. Even though it is not completely safe (the finalize method may not be called so that
  * there will be memory leakage), it allows to save some computations for serialization/deserialization. According to
  * performance tests we may gain approx 30% speed-up in computations that use points (e.g. ElGamal encryption)
  *
  * @param nativePoint native openssl point that will be freed in the finalize method. IMPORTANT: it should not be
  *                    freed by the constructor caller
  * @param ecGroup
  * @param bnCtx
  * @param openSslApi
  */
class ECPointCachedOpenSSL private[openssl] (protected val nativePoint: EC_POINT_PTR,
                                             override val ecGroup: EC_GROUP_PTR,
                                             override val bnCtx: BN_CTX_PTR,
                                             override val openSslApi: OpenSslAPI)
  extends ECPointOpenSSL(ECPointOpenSSL.nativePointToBytes(nativePoint, ecGroup, bnCtx, openSslApi).get, ecGroup, bnCtx, openSslApi) {

  // TODO: does this check slow down performance?
  require(openSslApi.EC_POINT_is_on_curve(ecGroup, nativePoint, bnCtx))

  override lazy val isInfinity: Boolean = openSslApi.EC_POINT_is_at_infinity(ecGroup, nativePoint)

  override def isOnCurve: Boolean = openSslApi.EC_POINT_is_on_curve(ecGroup, nativePoint, bnCtx)

  override def getHexString(form: PointConversionForm = PointConversionForm.POINT_CONVERSION_COMPRESSED): String =
    openSslApi.EC_POINT_point2hex(ecGroup, nativePoint, form, bnCtx)

  /**
    * Creates a copy of the cached native point.
    * IMPORTANT: it is responsibility of the caller to free EC_POINT object with EC_POINT_free
    */
  override def generateNativePoint: Try[EC_POINT_PTR] = Try {
    val point = openSslApi.EC_POINT_dup(nativePoint, ecGroup)
    if (point == null || point.address() == 0)
      throw new BadPointerException("Can not duplicate point")
    point
  }

  override def hashCode(): Int = util.Arrays.hashCode(encodedPoint)

  override def finalize(): Unit = {
    openSslApi.EC_POINT_free(nativePoint)
    super.finalize()
  }
}