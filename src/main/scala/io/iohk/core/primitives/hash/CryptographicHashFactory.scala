package io.iohk.core.primitives.hash

import io.iohk.core.primitives.hash.CryptographicHashFactory.AvailableHashes.AvailableHashes
import io.iohk.core.primitives.hash.bouncycastle.SHA3_256_HashBc

import scala.util.Try

object CryptographicHashFactory {

  object AvailableHashes extends Enumeration {
    type AvailableHashes = Value
    val SHA3_256_Bc = Value
  }

  def constructHash(hash: AvailableHashes): Try[CryptographicHash] = Try {
    hash match {
      case AvailableHashes.SHA3_256_Bc => SHA3_256_HashBc
      case _ => throw new IllegalArgumentException(s"Hash $hash is not supported")
    }
  }
}
