package treasury.crypto.core.primitives.dlog.openssl

import java.util

import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, ECGroupElement, GroupElement}
import treasury.crypto.core.serialization.Serializer
import treasury.crypto.native.OpenSslAPI
import treasury.crypto.native.OpenSslAPI.PointConversionForm
import treasury.crypto.native.OpenSslAPI.PointConversionForm.PointConversionForm
import treasury.crypto.native.OpenSslAPI.{BN_CTX_PTR, EC_GROUP_PTR, EC_POINT_PTR, PointConversionForm}

import scala.util.Try

/**
  * This class represents a point on the curve. Note that instead of holding a reference to the native EC_POINT object
  * we decided to hold serialized point, so that we don't care about managing native objects. Additionally we provide
  * methods for reconstructing EC_POINT from serialized representation.
  * An alternative approach would be to hold EC_POINT_PTR directly and override finalize method to free the native object when
  * it is not needed anymore. Such an approach was taken in SCAPI library. But using 'finalize' method is not reliable
  * and not guaranteed to be called at all, thus we avoid to keep native objects to prevent possible memory leakages,
  * even though it may cost a bit more because of additional conversions.
  *
  * @param bytes serialized point acquired through the EC_POINT_point2bn and BN_bn2bin. If the length is zero then
  *              it represents point at infinity.
  * @param ecGroup
  * @param bnCtx
  * @param openSslApi
  */
class ECPointOpenSSL(override val bytes: Array[Byte],
                     private val ecGroup: EC_GROUP_PTR,
                     private val bnCtx: BN_CTX_PTR,
                     private val openSslApi: OpenSslAPI) extends ECGroupElement {

  override lazy val isInfinity: Boolean = bytes.isEmpty

  override def multiply(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupOpenSSL])
    dlog.multiply(this, that)
  }

  override def pow(exp: BigInt)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupOpenSSL])
    dlog.exponentiate(this, exp)
  }

  override def divide(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupOpenSSL])
    dlog.divide(this, that)
  }

  override def inverse()(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    require(dlog.isInstanceOf[ECDiscreteLogGroupOpenSSL])
    dlog.inverse(this)
  }

  override def getX: BigInt = ???

  override def getY: BigInt = ???

  override type M = this.type
  override def serializer: Serializer[ECPointOpenSSL.this.type] = ???

  override def equals(o: Any): Boolean = {
    o match {
      case that: ECPointOpenSSL => o.isInstanceOf[ECPointOpenSSL] && (this.hashCode == that.hashCode)
      case _ => false
    }
  }

  override def hashCode(): Int = util.Arrays.hashCode(bytes)

  /**
    * This method is mostly for testing purposes
    */
  def isOnCurve: Boolean =
    generateNativePoint.map { p =>
      val res = openSslApi.EC_POINT_is_on_curve(ecGroup, p, bnCtx)
      openSslApi.EC_POINT_free(p)
      res
    }.getOrElse(false)

  def getHexString(form: PointConversionForm = PointConversionForm.POINT_CONVERSION_COMPRESSED): String = Try {
    val nativePoint = generateNativePoint.get
    val string = openSslApi.EC_POINT_point2hex(ecGroup, nativePoint, form, bnCtx)
    openSslApi.EC_POINT_free(nativePoint)
    string
  }.getOrElse("N/A")

  /**
    * Creates a native openssl object EC_POINT.
    * IMPORTANT: it is responsibility of the caller to free EC_POINT object with EC_POINT_free
    */
  def generateNativePoint: Try[EC_POINT_PTR] = {
    if (bytes.length == 0) // point at infinity
      ECPointOpenSSL.generateNativeInfinityPoint(ecGroup, bnCtx, openSslApi)
    else
      ECPointOpenSSL.generateNativePointFromBytes(bytes, ecGroup, bnCtx, openSslApi)
  }
}

object ECPointOpenSSL {

  def apply(point: EC_POINT_PTR, ecGroup: EC_GROUP_PTR, bnCtx: BN_CTX_PTR, openSslApi: OpenSslAPI): Try[ECPointOpenSSL] = Try {
    OpenSslAPI.checkPointerWithException(point, "Can not create ECPointOpenSSL object because of the bad pointer")
    require(openSslApi.EC_POINT_is_on_curve(ecGroup, point, bnCtx), "Can not create ECPointOpenSSL object from the EC_POINT that is not on the curve")

    val bytes = nativePointToBytes(point, ecGroup, bnCtx, openSslApi).get
    new ECPointOpenSSL(bytes, ecGroup, bnCtx, openSslApi)
  }

  def getInfinityPoint(ecGroup: EC_GROUP_PTR, bnCtx: BN_CTX_PTR, openSslApi: OpenSslAPI): ECPointOpenSSL = {
    new ECPointOpenSSL(Array(), ecGroup, bnCtx, openSslApi)
  }

  /**
    * Creates a native openssl object EC_POINT that represents point at infinity.
    * IMPORTANT: it is responsibility of the caller to free EC_POINT object with EC_POINT_free
    */
  protected def generateNativeInfinityPoint(ecGroup: EC_GROUP_PTR,
                                  bnCtx: BN_CTX_PTR,
                                  openSslApi: OpenSslAPI): Try[EC_POINT_PTR] = Try {
    val point = openSslApi.EC_POINT_new(ecGroup)
    if (point == null || point.address == 0)
      throw new Exception("Can not create point! Maybe something is wrong with EC group???")
    if (!openSslApi.EC_POINT_set_to_infinity(ecGroup, point)) {
      openSslApi.EC_POINT_free(point)
      throw new Exception("Can not set point to infinity!")
    }
    point
  }

  /**
    * Creates a native openssl object EC_POINT from bytes.
    * IMPORTANT: it is responsibility of the caller to free EC_POINT object with EC_POINT_free
    */
  protected def generateNativePointFromBytes(bytes: Array[Byte],
                                   ecGroup: EC_GROUP_PTR,
                                   bnCtx: BN_CTX_PTR,
                                   openSslApi: OpenSslAPI): Try[EC_POINT_PTR] = Try {
    require(bytes.length > 0)

    val point = openSslApi.EC_POINT_new(ecGroup)
    if (point == null || point.address == 0)
      throw new Exception("Can not create point. Is something wrong with ecGroup?")

    if (!openSslApi.EC_POINT_oct2point(ecGroup, point, bytes, bytes.length, bnCtx)) {
      openSslApi.EC_POINT_free(point)
      throw new IllegalArgumentException("Can not create point from the provided bytes")
    }
    point
  }

  /**
    * Returns an array of bytes that encodes the point. In case of point at infinity, it returns an empty Array[Byte]
    */
  protected def nativePointToBytes(point: EC_POINT_PTR,
                         ecGroup: EC_GROUP_PTR,
                         bnCtx: BN_CTX_PTR,
                         openSslApi: OpenSslAPI): Try[Array[Byte]] = Try {
    if (openSslApi.EC_POINT_is_at_infinity(ecGroup, point)) {
      Array()
    } else {
      // first call to know what buffer size we need
      val len = openSslApi.EC_POINT_point2oct(ecGroup, point, PointConversionForm.POINT_CONVERSION_COMPRESSED, null, 0, bnCtx)
      if (len <= 0)
        throw new Exception("Can not convert point to bytes!")

      // second call to actually fill the buffer
      val buf = new Array[Byte](len)
      val resLen = openSslApi.EC_POINT_point2oct(ecGroup, point, PointConversionForm.POINT_CONVERSION_COMPRESSED, buf, len, bnCtx)
      if (resLen <= 0)
        throw new Exception("Can not convert point to bytes!")

      buf
    }
  }

}
