package io.iohk.core.crypto.primitives.dlog.openssl

import java.util

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, ECGroupElement, GroupElement}
import io.iohk.core.serialization.Serializer
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, ECGroupElement, GroupElement}
import io.iohk.core.serialization.Serializer
import io.iohk.core.native.OpenSslAPI
import io.iohk.core.native.OpenSslAPI.PointConversionForm.PointConversionForm
import io.iohk.core.native.OpenSslAPI.{BN_CTX_PTR, EC_GROUP_PTR, EC_POINT_PTR, PointConversionForm}

import scala.util.Try

/**
  * This class represents a point on the curve. Note that it holds a reference to the native EC_POINT object which is
  * freed in the finalize method. In general, the method finalize is not guaranteed to be called upon object descrutcion,
  * so the memory leaks are possible.
  * An alternative approach would be to hold only serialized point and recover native object only when operations to be
  * performed and free it right after that. Such an approach comes with performance penalty (approx 30% slower), thus
  * we chosed in favour of the first approach.
  *
  * @param nativePoint pointer to the native object. IMPORTANT: it is responsibility of the ECPointOpenSSL object to
  *                    free the native point. Caller should not do this, otherwise the system may crash
  * @param group
  */
class ECPointOpenSSL private (val nativePoint: EC_POINT_PTR,
                              val group: ECDiscreteLogGroupOpenSSL) extends ECGroupElement {

  private val (ecGroup, bnCtx, openSslApi) = (group.ecGroup, group.bnCtx, group.openSslApi)
  require(openSslApi.EC_POINT_is_on_curve(ecGroup, nativePoint, bnCtx))

  lazy val encodedPoint: Array[Byte] = ECPointOpenSSL.nativePointToBytes(nativePoint, ecGroup, bnCtx, openSslApi).get

  override lazy val isInfinity: Boolean = openSslApi.EC_POINT_is_at_infinity(ecGroup, nativePoint)

  override def multiply(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    group.multiply(this, that)
  }

  override def pow(exp: BigInt)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    group.exponentiate(this, exp)
  }

  override def divide(that: GroupElement)(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    group.divide(this, that)
  }

  override def inverse()(implicit dlog: DiscreteLogGroup): Try[GroupElement] = {
    group.inverse(this)
  }

  /**
    * @return (x,y) coordinates of the point
    */
  def getAffineCoordinates: (BigInt, BigInt) = if (isInfinity) (-1,-1) else {
    val bnX = openSslApi.BN_new
    val bnY = openSslApi.BN_new
    val res = openSslApi.EC_POINT_get_affine_coordinates(ecGroup, nativePoint, bnX, bnY, bnCtx)
    require(res == 1)

    val buf = new Array[Byte](64)

    val len = openSslApi.BN_bn2bin(bnX, buf)
    require(len <= 64)
    val X = BigInt(1, buf.take(len))

    val len2 = openSslApi.BN_bn2bin(bnY, buf)
    require(len2 <= 64)
    val Y = BigInt(1, buf.take(len2))

    openSslApi.BN_free(bnX)
    openSslApi.BN_free(bnY)
    (X,Y)
  }

  override def getX: BigInt = getAffineCoordinates._1

  override def getY: BigInt = getAffineCoordinates._2

  override type M = ECPointOpenSSL
  override type DECODER = ECDiscreteLogGroupOpenSSL
  override def serializer: Serializer[M, DECODER] = ECPointOpenSSLSerializer

  override def equals(o: Any): Boolean = {
    o match {
      case that: ECPointOpenSSL => 0 == openSslApi.EC_POINT_cmp(ecGroup, this.nativePoint, that.nativePoint, bnCtx)
      case _ => false
    }
  }

  override def hashCode(): Int = util.Arrays.hashCode(encodedPoint)

  override def toString: String = getHexString()

  override def finalize(): Unit = {
    openSslApi.EC_POINT_free(nativePoint)
    super.finalize()
  }

  /**
    * This method is mostly for testing purposes
    */
  def isOnCurve: Boolean = openSslApi.EC_POINT_is_on_curve(ecGroup, nativePoint, bnCtx)

  def getHexString(form: PointConversionForm = PointConversionForm.POINT_CONVERSION_COMPRESSED): String =
    openSslApi.EC_POINT_point2hex(ecGroup, nativePoint, form, bnCtx)
}

object ECPointOpenSSL {

  /**
    * Creates a ECPointOpenSSL. Note that from now the responsibility to free the point is on the ECPointOpenSSL object,
    * so that the caller MUST NOT free the point.
    */
  def apply(point: EC_POINT_PTR, group: ECDiscreteLogGroupOpenSSL): Try[ECPointOpenSSL] = Try {
    OpenSslAPI.checkPointerWithException(point, "Can not create ECPointOpenSSL object because of the bad pointer")
    new ECPointOpenSSL(point, group)
  }

  /**
    * Creates a native openssl object EC_POINT from bytes.
    * IMPORTANT: it is responsibility of the caller to free EC_POINT object with EC_POINT_free
    */
  protected[openssl] def generateNativePointFromBytes(bytes: Array[Byte],
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
  protected[openssl] def nativePointToBytes(point: EC_POINT_PTR,
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

object ECPointOpenSSLSerializer extends Serializer[ECPointOpenSSL, ECDiscreteLogGroupOpenSSL] {

  override def toBytes(obj: ECPointOpenSSL): Array[Byte] = {
    if (obj.isInfinity) // handle infinity point separately, encode it just as a 1-byte array that contains zero
      Array(0.toByte)
    else
      obj.encodedPoint
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[ECDiscreteLogGroupOpenSSL]): Try[ECPointOpenSSL] = Try {
    val group = decoder.get
    if (bytes.length == 1 && bytes(0) == 0) // point at infinity
      group.infinityPoint.asInstanceOf[ECPointOpenSSL]
    else {
      val point = ECPointOpenSSL.generateNativePointFromBytes(bytes, group.ecGroup, group.bnCtx, group.openSslApi).get
      ECPointOpenSSL(point, group).get
    }
  }
}
