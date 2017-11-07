package treasury.crypto.nizk

import treasury.crypto.core.{Cryptosystem, One, TimeUtils}
import treasury.crypto.nizk.unitvectornizk.ZeroOrOneSigmaNIZK.ZeroOrOneSigmaNIZKProof
import treasury.crypto.nizk.unitvectornizk.{ZeroOrOneBZNIZK, ZeroOrOneSigmaNIZK}

class ZeroOrOneNIZKPerformance {
  private val cs = new Cryptosystem
  private val (privKey, pubKey) = cs.createKeyPair

  def run() = {
    val r = cs.getRand
    val c = cs.encrypt(pubKey, r, One)

    TimeUtils.accurate_time("BZ NIZK creation (for single ciphertext): ", ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, One, c, r))
    val proofBZ = ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, One, c, r)
    TimeUtils.accurate_time("BZ NIZK verification (for single ciphertext): ", ZeroOrOneBZNIZK.verifyNIZK(cs, pubKey, c, proofBZ))
    println("BZ NIZK proof size: " + (proofBZ.A._1.getEncoded(true).length*4 + proofBZ.f.toByteArray.length*3) + " bytes")

    println

    TimeUtils.accurate_time("SigmaOR NIZK creation (for single ciphertext): ", ZeroOrOneSigmaNIZK.produceNIZK(cs, pubKey, One, c, r))
    val proofSigma = ZeroOrOneSigmaNIZK.produceNIZK(cs, pubKey, One, c, r)
    TimeUtils.accurate_time("SigmaOR NIZK verification (for single ciphertext): ", ZeroOrOneSigmaNIZK.verifyNIZK(cs, pubKey, c, proofSigma))
    println("SigmaOR NIZK proof size: " + (proofSigma.A1.getEncoded(true).length*4 + proofSigma.z1.toByteArray.length*2 + proofSigma.e2.length) + " bytes")
  }
}

object ZeroOrOneNIZKPerformance {
  def main(args: Array[String]): Unit = {
    new ZeroOrOneNIZKPerformance().run
  }
}
