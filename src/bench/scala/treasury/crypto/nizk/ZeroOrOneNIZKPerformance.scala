package treasury.crypto.nizk

import treasury.crypto.core.encryption.elgamal.LiftedElGamalEnc
import treasury.crypto.core.encryption.encryption
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import treasury.crypto.core.primitives.hash.CryptographicHashFactory
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import treasury.crypto.core.{Cryptosystem, One, TimeUtils}
import treasury.crypto.nizk.unitvectornizk.ZeroOrOneSigmaNIZK.ZeroOrOneSigmaNIZKProof
import treasury.crypto.nizk.unitvectornizk.{ZeroOrOneBZNIZK, ZeroOrOneSigmaNIZK}

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
