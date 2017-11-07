package treasury.crypto.nizk

import treasury.crypto.core.{Cryptosystem, One, TimeUtils}
import treasury.crypto.nizk.shvzk.{SHVZKGen, SHVZKVerifier}
import treasury.crypto.nizk.unitvectornizk.{UVSumNIZK, ZeroOrOneBZNIZK, ZeroOrOneSigmaNIZK}

class ExpertBallotPerformance {
  private val cs = new Cryptosystem
  private val (privKey, pubKey) = cs.createKeyPair

  def run() = {
    val C = for (i <- 0 until 3) yield {
      val r = cs.getRand
      (cs.encrypt(pubKey, r, One), r)
    }

    TimeUtils.accurate_time("BZ NIZK creation for expert ballot (3 ciphertexts): ", {
      C.foreach(c => ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, One, c._1, c._2))
      UVSumNIZK.produceNIZK(cs, pubKey, C)
    })
    val proofBZ = C.map(c => ZeroOrOneBZNIZK.produceNIZK(cs, pubKey, One, c._1, c._2))
    val sumNIZK = UVSumNIZK.produceNIZK(cs, pubKey, C)
    TimeUtils.accurate_time("BZ NIZK verification for expert ballot (3 ciphertexts): ", {
      proofBZ.zip(C.map(_._1)).foreach(x => ZeroOrOneBZNIZK.verifyNIZK(cs, pubKey, x._2, x._1))
      UVSumNIZK.verifyNIZK(cs, pubKey, C.map(_._1), sumNIZK)
    })
    println("BZ NIZK proof size: " +
      ((proofBZ.head.A._1.getEncoded(true).length*4 + proofBZ.head.f.toByteArray.length*3)*3 +
        sumNIZK.A1.getEncoded(true).size*2 + sumNIZK.z.toByteArray.size) + " bytes")

    println

    TimeUtils.accurate_time("SigmaOR NIZK creation for expert ballot (3 ciphertexts): ", {
      C.foreach(c => ZeroOrOneSigmaNIZK.produceNIZK(cs, pubKey, One, c._1, c._2))
      UVSumNIZK.produceNIZK(cs, pubKey, C)
    })
    val proofSigma = C.map(c => ZeroOrOneSigmaNIZK.produceNIZK(cs, pubKey, One, c._1, c._2))
    TimeUtils.accurate_time("SigmaOR NIZK verification for expert ballot (3 ciphertexts): ", {
      proofSigma.zip(C.map(_._1)).foreach(x => ZeroOrOneSigmaNIZK.verifyNIZK(cs, pubKey, x._2, x._1))
      UVSumNIZK.verifyNIZK(cs, pubKey, C.map(_._1), sumNIZK)
    })
    println("SigmaOR NIZK proof size: " +
      ((proofBZ.head.A._1.getEncoded(true).length*4 + proofBZ.head.f.toByteArray.length*3)*3 +
        sumNIZK.A1.getEncoded(true).size*2 + sumNIZK.z.toByteArray.size) + " bytes")

    println

    TimeUtils.accurate_time("SHV NIZK creation for expert ballot (3 ciphertexts): ", {
      new SHVZKGen(cs, pubKey, C.map(_._1), 0, C.map(_._2)).produceNIZK
    })
    val shvzkProof = new SHVZKGen(cs, pubKey, C.map(_._1), 0, C.map(_._2)).produceNIZK
    TimeUtils.accurate_time("SHV NIZK verification for expert ballot (3 ciphertexts): ", {
      new SHVZKVerifier(cs, pubKey, C.map(_._1), shvzkProof).verifyProof
    })
    val proofsize: Int =
      shvzkProof.R.toByteArray.size +
      shvzkProof.zwv.size * shvzkProof.zwv(0)._1.toByteArray.size * 3 +
      shvzkProof.Dk.size * shvzkProof.Dk(0)._1.getEncoded(true).size * 2 +
      shvzkProof.IBA.size * shvzkProof.IBA(0)._1.getEncoded(true).size * 3
    println("SHV NIZK proof size: " + proofsize + " bytes")
  }
}

object ExpertBallotPerformance {
  def main(args: Array[String]): Unit = {
    new ExpertBallotPerformance().run
  }
}