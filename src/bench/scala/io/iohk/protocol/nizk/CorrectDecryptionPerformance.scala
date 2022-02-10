package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.dlog_encryption.DLogEncryption
import io.iohk.protocol.common.dlog_encryption.NIZKs.CorrectDecryptionNIZK.CorrectDecryption
import io.iohk.protocol.common.dlog_encryption.NIZKs.CorrectDecryptionNIZK.CorrectDecryption.{Statement, Witness}

// Performance of the CorrectDecryption NIZK is independent of segment size (BaseCodec.defaultBase) used for DLogEncryption encryption
class CorrectDecryptionPerformance {

  private val context = new CryptoContext(None)
  import context.group

  def run(): Unit = {
    val sampleSize = 100

    val (sk, pk) = encryption.createKeyPair(context.group).get
    val plaintext = group.createRandomNumber
    val ciphertext = DLogEncryption.encrypt(plaintext, pk).get._1

    val st = Statement(pk, plaintext, ciphertext)
    val w = Witness(sk)

    val nizk = CorrectDecryption(st)
    assert(nizk.verify(nizk.prove(w))) // warming up

    val (proofs, proverTime) = TimeUtils.get_time_average_s(
      "CorrectDecryption prover time:",
      (0 until sampleSize).map(_ => nizk.prove(w)),
      sampleSize
    )
    assert(proofs.length == sampleSize)

    println
    val (results, verifierTime) = TimeUtils.get_time_average_s(
      "CorrectDecryption verifier time:",
      proofs.map(nizk.verify),
      proofs.length
    )
    assert(results.forall(_.equals(true)))
    println("\nCorrectDecryption proof size: " + SizeUtils.getMaxSize(proofs) + " B")
  }
}

object CorrectDecryptionPerformance {
  def main(args: Array[String]): Unit = {
    new CorrectDecryptionPerformance().run()
  }
}
