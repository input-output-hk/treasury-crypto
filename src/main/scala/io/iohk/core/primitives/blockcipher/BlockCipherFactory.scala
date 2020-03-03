package io.iohk.core.primitives.blockcipher

import io.iohk.core.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers.AvailableBlockCiphers
import io.iohk.core.primitives.blockcipher.bouncycastle.AES128_GSM_Bc

import scala.util.Try

object BlockCipherFactory {

  object AvailableBlockCiphers extends Enumeration {
    type AvailableBlockCiphers = Value
    val AES128_BSM_Bc = Value
  }

  def constructBlockCipher(cipher: AvailableBlockCiphers): Try[BlockCipher] = Try {
    cipher match {
      case AvailableBlockCiphers.AES128_BSM_Bc => AES128_GSM_Bc
      case _ => throw new IllegalArgumentException(s"Cipher $cipher is not supported")
    }
  }
}
