package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.dlog_encryption.DLogEncryption
import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectEncryption.Witness
import org.scalatest.FunSuite

class CorrectEncryptionTests extends FunSuite {

  private val context = new CryptoContext(Option(CryptoContext.generateRandomCRS))
  private val dlogGroup = context.group

  import context.group

  test("CorrectEncryption"){

    val encryptionsNum = 20
    val pubKey = encryption.createKeyPair.get._2

    val msgs = for(_ <- 0 until encryptionsNum) yield dlogGroup.createRandomNumber
    val encryptions = msgs.map(msg => DLogEncryption.encrypt(msg, pubKey).get)

    val cts = encryptions.map(_._1) // ciphertexts
    val rs = encryptions.map(_._2)  // randomnesses used for ciphertexts

    val proof = CorrectEncryption(cts, pubKey, dlogGroup).prove(Witness(msgs, rs, dlogGroup))
    assert(CorrectEncryption(cts, pubKey, dlogGroup).verify(proof))
  }
}
