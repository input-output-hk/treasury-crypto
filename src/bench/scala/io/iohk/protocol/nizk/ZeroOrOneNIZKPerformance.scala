package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.core.{One, TimeUtils}
import io.iohk.protocol.nizk.unitvectornizk.{ZeroOrOneBZNIZK, ZeroOrOneSigmaNIZK}

class ZeroOrOneNIZKPerformance {

  implicit val group = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  implicit val hash = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val (privKey, pubKey) = encryption.createKeyPair.get

  def run() = {
    val r = group.createRandomNumber
    val c = LiftedElGamalEnc.encrypt(pubKey, r, One).get

    TimeUtils.accurate_time("BZ NIZK creation (for single ciphertext): ", ZeroOrOneBZNIZK.produceNIZK(pubKey, One, c, r).get)
    val proofBZ = ZeroOrOneBZNIZK.produceNIZK(pubKey, One, c, r).get
    TimeUtils.accurate_time("BZ NIZK verification (for single ciphertext): ", ZeroOrOneBZNIZK.verifyNIZK(pubKey, c, proofBZ))
    println("BZ NIZK proof size: " + (proofBZ.A.c1.bytes.length*4 + proofBZ.f.toByteArray.length*3) + " bytes")

    println

    TimeUtils.accurate_time("SigmaOR NIZK creation (for single ciphertext): ", ZeroOrOneSigmaNIZK.produceNIZK(pubKey, One, c, r).get)
    val proofSigma = ZeroOrOneSigmaNIZK.produceNIZK(pubKey, One, c, r).get
    TimeUtils.accurate_time("SigmaOR NIZK verification (for single ciphertext): ", ZeroOrOneSigmaNIZK.verifyNIZK(pubKey, c, proofSigma))
    println("SigmaOR NIZK proof size: " + (proofSigma.A1.bytes.length*4 + proofSigma.z1.toByteArray.length*2 + proofSigma.e2.length) + " bytes")
  }
}

object ZeroOrOneNIZKPerformance {
  def main(args: Array[String]): Unit = {
    new ZeroOrOneNIZKPerformance().run
  }
}
