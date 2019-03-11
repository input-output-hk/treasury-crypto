package treasury.crypto.native

import jnr.ffi.Pointer
import treasury.crypto.native.OpenSslAPI._
import treasury.crypto.native.OpenSslAPI.PointConversionForm.PointConversionForm

trait OpenSslAPI {

  // bn.h
  def BN_CTX_new: BN_CTX_PTR
  def BN_bin2bn(s: Array[Byte], len: Int, out: BIGNUM_PTR): BIGNUM_PTR
  def BN_bn2bin(p: BIGNUM_PTR, out: Array[Byte]): Int
  def BN_div(div: BIGNUM_PTR, remainder: BIGNUM_PTR, num: BIGNUM_PTR, mod: BIGNUM_PTR, bnCtx: BN_CTX_PTR): Boolean
  def BN_nnmod(res: BIGNUM_PTR, a: BIGNUM_PTR, mod: BIGNUM_PTR, bnCtx: BN_CTX_PTR): Boolean
  def BN_sub(res: BIGNUM_PTR, a: BIGNUM_PTR, b: BIGNUM_PTR): Boolean
  def BN_set_negative(b: BIGNUM_PTR, n: Int): Unit
  def BN_is_negative(b: BIGNUM_PTR): Boolean
  def BN_free(p: BIGNUM_PTR)

  // ec.h
  def EC_get_builtin_curves(curve: EC_BUILTIN_CURVE_PTR, nitems: Int): Int
  def EC_curve_nid2nist(nid: Int): String
  def EC_curve_nist2nid(name: String): Int

  def EC_GROUP_new_curve_GFp(p: BIGNUM_PTR, a: BIGNUM_PTR, b: BIGNUM_PTR, bnCtx: BN_CTX_PTR): EC_GROUP_PTR
  def EC_GROUP_new_by_curve_name(nid: Int): EC_GROUP_PTR
  def EC_GROUP_set_generator(group: EC_GROUP_PTR, generator: EC_POINT_PTR, order: BIGNUM_PTR, cofactor: BIGNUM_PTR): Boolean
  // IMPORTANT: "get0" suffix means that function returns an internal pointer! IT MUST NOT BE FREED BY THE CALLER!
  def EC_GROUP_get0_generator(group: EC_GROUP_PTR): EC_POINT_PTR
  // IMPORTANT: "get0" suffix means that function returns an internal pointer! IT MUST NOT BE FREED BY THE CALLER!
  def EC_GROUP_get0_order(group: EC_GROUP_PTR): BIGNUM_PTR
  def EC_GROUP_check(group: EC_GROUP_PTR, bnCtx: BN_CTX_PTR): Boolean
  def EC_GROUP_free(group: EC_GROUP_PTR)

  def EC_POINT_new(group: EC_GROUP_PTR): EC_POINT_PTR
  def EC_POINT_free(point: EC_POINT_PTR)
  def EC_POINT_clear_free(point: EC_POINT_PTR)
  def EC_POINT_point2hex(group: EC_GROUP_PTR, point: EC_POINT_PTR, form: PointConversionForm, bnCtx: BN_CTX_PTR): String
  def EC_POINT_hex2point(group: EC_GROUP_PTR, point: String, outPoint: EC_POINT_PTR, bnCtx: BN_CTX_PTR): EC_POINT_PTR
  def EC_POINT_bn2point(group: EC_GROUP_PTR, bigNum: BIGNUM_PTR, outPoint: EC_POINT_PTR, bnCtx: BN_CTX_PTR): EC_POINT_PTR
  def EC_POINT_point2bn(group: EC_GROUP_PTR, point: EC_POINT_PTR, form: PointConversionForm, bigNum: BIGNUM_PTR, bnCtx: BN_CTX_PTR): BIGNUM_PTR
  def EC_POINT_is_on_curve(group: EC_GROUP_PTR, point: EC_POINT_PTR, bnCtx: BN_CTX_PTR): Boolean
  def EC_POINT_set_to_infinity(group: EC_GROUP_PTR, point: EC_POINT_PTR): Boolean
  def EC_POINT_is_at_infinity(group: EC_GROUP_PTR, point: EC_POINT_PTR): Boolean
  def EC_POINT_point2oct(group: EC_GROUP_PTR, point: EC_POINT_PTR, pointConversionForm: PointConversionForm, buf: Array[Byte], len: Int, bnCtx: BN_CTX_PTR): Int
  def EC_POINT_oct2point(group: EC_GROUP_PTR, point: EC_POINT_PTR, buf: Array[Byte], len: Int, bnCtx: BN_CTX_PTR): Boolean
  def EC_POINT_mul(group: EC_GROUP_PTR, out: EC_POINT_PTR, multiplier: BIGNUM_PTR, base: EC_POINT_PTR, exponent: BIGNUM_PTR, bnCtx: BN_CTX_PTR): Boolean
  def EC_POINT_add(group: EC_GROUP_PTR, out: EC_POINT_PTR, point1: EC_POINT_PTR, point2: EC_POINT_PTR, bnCtx: BN_CTX_PTR): Boolean
  def EC_POINT_invert(group: EC_GROUP_PTR, point: EC_POINT_PTR, bnCtx: BN_CTX_PTR): Boolean
}

object OpenSslAPI {

  type BN_CTX_PTR = Pointer
  type EC_GROUP_PTR = Pointer
  type EC_POINT_PTR = Pointer
  type BIGNUM_PTR = Pointer
  type EC_BUILTIN_CURVE_PTR = Pointer

  /** Enum for the point conversion form as defined in X9.62 (ECDSA) for the encoding of a elliptic curve point (x,y) */
  /* PORTED FROM ec.h */
  object PointConversionForm extends Enumeration {
    type PointConversionForm = Int
    /** the point is encoded as z||x, where the octet z specifies which solution of the quadratic equation y is  */
    val POINT_CONVERSION_COMPRESSED = 2
    /** the point is encoded as z||x||y, where z is the octet 0x04  */
    val POINT_CONVERSION_UNCOMPRESSED = 4
    /** the point is encoded as z||x||y, where the octet z specifies which solution of the quadratic equation y is  */
    val POINT_CONVERSION_HYBRID = 6
  }

  @throws[BadPointerException]
  def checkPointerWithException(p: Pointer, errorMsg: String): Unit = {
    if (p == null || p.address() == 0)
      throw new BadPointerException(errorMsg)
  }

  class BadPointerException(errorMsg: String) extends Exception(errorMsg)
}