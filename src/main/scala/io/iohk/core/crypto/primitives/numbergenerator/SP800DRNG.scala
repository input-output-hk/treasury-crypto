package io.iohk.core.crypto.primitives.numbergenerator

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG
import org.bouncycastle.crypto.prng.{EntropySource, EntropySourceProvider}
import io.iohk.core.crypto.primitives.hash.bouncycastle.SHA3_256_HashBc

class SP800DRNG(seed: Array[Byte]) extends DeterministicRandomNumberGenerator(seed) {

  private val drng = new HashSP800DRBG(new SHA256Digest(), 256, new SP800DRNG.SingleEntropySourceProvider(SHA3_256_HashBc.hash(seed)).get(256), null, null)

  override def algorithmName: String = "SP800 Deterministic Random Number Generator (Bouncy Castle)"

  override def nextBytes(length: Int): Array[Byte] = {
    val bytes = new Array[Byte](length)
    val len = drng.generate(bytes, null, false)
    require(len == length * 8)
    bytes
  }
}

object SP800DRNG {

  // The implementation is based on: https://www.cryptoworkshop.com/ximix/coverage/org.cryptoworkshop.ximix.common.util.challenge/SeededChallenger.java.html
  private class SingleEntropySourceProvider (val data: Array[Byte]) extends EntropySourceProvider {

    override def get(bitsRequired: Int): EntropySource =
      new EntropySource() {
        private var index = 0

        override def isPredictionResistant: Boolean = true

        override def getEntropy: Array[Byte] = {
          val rv = new Array[Byte](bitsRequired / 8)
          if (data.length < (index + rv.length)) throw new IllegalStateException("Insufficient entropy - need " + rv.length + " bytes for challenge seed.")
          System.arraycopy(data, index, rv, 0, rv.length)
          index += bitsRequired / 8
          rv
        }

        override def entropySize: Int = bitsRequired
      }
  }
}