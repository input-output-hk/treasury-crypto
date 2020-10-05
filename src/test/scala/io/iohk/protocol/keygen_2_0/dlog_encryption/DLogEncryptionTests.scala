package io.iohk.protocol.keygen_2_0.dlog_encryption

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.math.LagrangeInterpolation
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

//  test("interpolation"){
//    assert(LagrangeInterpolation.testInterpolation(context, 4))
//  }
}
