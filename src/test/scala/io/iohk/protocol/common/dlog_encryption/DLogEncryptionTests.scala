package io.iohk.protocol.common.dlog_encryption

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.dlog_encryption.{DLogCiphertextSerializer, DLogEncryption}
import io.iohk.protocol.common.math.LagrangeInterpolationTests
import org.scalatest.FunSuite

import scala.util.Success

class DLogEncryptionTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group
  private val n = dlogGroup.groupOrder

  import context.group

  test("encryption_decryption"){
    val (privKey, pubKey) = encryption.createKeyPair.get
    val msg = BigInt(n.bitLength, util.Random).mod(n)
    assert(msg == DLogEncryption.decrypt(DLogEncryption.encrypt(msg, pubKey).get._1, privKey).get)
  }

  test("serialization"){
    val (privKey, pubKey) = encryption.createKeyPair.get
    val msg = BigInt(n.bitLength, util.Random).mod(n)
    val ct = DLogEncryption.encrypt(msg, pubKey).get._1

    assert(ct.equals(DLogCiphertextSerializer.parseBytes(ct.bytes, Some(context.group)).get))
  }

//  test("interpolation"){
//    assert(LagrangeInterpolation.testInterpolation(context, 4))
//  }
}
