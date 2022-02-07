package io.iohk.protocol.common.dlog_encryption.NIZK

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.dlog_encryption.DLogEncryption
import io.iohk.protocol.common.dlog_encryption.NIZKs.CorrectDecryptionNIZK.CorrectDecryption.{Statement, Witness}
import io.iohk.protocol.common.dlog_encryption.NIZKs.CorrectDecryptionNIZK.CorrectDecryption
import org.scalatest.FunSuite

class CorrectDecryptionTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))

  import context.group

  test("CorrectDecryption"){
    for(_ <- 0 until 100){
      val (sk, pk) = encryption.createKeyPair(context.group).get
      val plaintext = group.createRandomNumber
      val ciphertext = DLogEncryption.encrypt(plaintext, pk).get._1

      val st = Statement(pk, plaintext, ciphertext)
      assert(
        CorrectDecryption(st).verify(
          CorrectDecryption(st).prove(Witness(sk))
        )
      )
    }
  }
}
