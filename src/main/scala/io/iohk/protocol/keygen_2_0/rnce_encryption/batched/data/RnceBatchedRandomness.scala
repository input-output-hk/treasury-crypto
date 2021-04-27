package io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data

import io.iohk.core.crypto.encryption.Randomness

case class RnceBatchedRandomness(R: Seq[Randomness]){
  val size: Int = R.foldLeft(0)((sum, r) => sum + r.toByteArray.length)
}
