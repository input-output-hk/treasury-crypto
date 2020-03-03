package io.iohk.core.crypto.primitives.dlog

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups.AvailableGroups

/**
  * This class defines parameters of the group for testing. Normally these parameters should be extracted from
  * official specifications.
  */
object GroupParameters {

  /**
    * Currently we check for correctness only the group generator and order, because they are accessible from the
    * DiscreteLogGroup interface. Some specific group types (e.g. based on elliptic curves) may have additional
    * parameters to check (such as curve parameters, etc.).
    *
    * @param generator Encoded generator, usually it is a hex representation which depends on specific group type
    * @param order BigInt encoded as hex string
    */
  class Parameters(val generator: String, val order: String)

  /**
    * @param generator Encoded generator, it should be a compressed hex encoding of a point
    * @param generatorX hex-encoded X coordinate of the generator point (uncompressed)
    * @param generatorY hex-encoded Y coordinate of the generator point (uncompressed)
    * @param order BigInt encoded as hex string
    * @param fieldCharacteristic BigInt encoded as a hex string that represent characteristic of the field over which curve
    *                   equation is defined
    * @param A BigInt encoded as a hex string that represents parameter of the curve equation
    * @param B BigInt encoded as a hex string that represents parameter of the curve equation
    */
  class EllipticCurveParameters(generator: String,
                                order: String,
                                val generatorX: String,
                                val generatorY: String,
                                val fieldCharacteristic: String,
                                val A: String,
                                val B: String) extends Parameters(generator, order)


  /**
    * TODO: maybe provide group parameters through some parsable resource (e.g. JSON) and just parse them here instead
    * of manual hardcoding
    */
  val secp256k1Params =
    new EllipticCurveParameters(
      "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
      "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
      "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
      "0",
      "7")

  val secp256r1Params =
    new EllipticCurveParameters(
      "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
      "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
      "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
      "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
      "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
      "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
      "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")

  def getGroupParameters(group: AvailableGroups): Parameters = {
    group match {
      case AvailableGroups.BC_secp256k1 | AvailableGroups.OpenSSL_secp256k1 => secp256k1Params
      case AvailableGroups.BC_secp256r1 | AvailableGroups.OpenSSL_secp256r1 => secp256r1Params
      case _ => throw new IllegalArgumentException(s"No parameters for $group")
    }
  }
}
