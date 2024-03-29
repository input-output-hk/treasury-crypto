package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKVerifier}
import io.iohk.protocol.nizk.unitvectornizk.{UVSumNIZK, ZeroOrOneBZNIZK, ZeroOrOneSigmaNIZK}

class ExpertBallotPerformance {

  implicit val group = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  implicit val hash = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val (privKey, pubKey) = encryption.createKeyPair.get
  private val crs = group.createRandomGroupElement.get

  def run() = {
    val C = for (i <- 0 until 3) yield {
      val r = group.createRandomNumber
      (LiftedElGamalEnc.encrypt(pubKey, r, 1).get, r)
    }

    TimeUtils.accurate_time("BZ NIZK creation for expert ballot (3 ciphertexts): ", {
      C.foreach(c => ZeroOrOneBZNIZK.produceNIZK(pubKey, 1, c._1, c._2).get)
      UVSumNIZK.produceNIZK(pubKey, C).get
    })
    val proofBZ = C.map(c => ZeroOrOneBZNIZK.produceNIZK(pubKey, 1, c._1, c._2).get)
    val sumNIZK = UVSumNIZK.produceNIZK(pubKey, C).get
    TimeUtils.accurate_time("BZ NIZK verification for expert ballot (3 ciphertexts): ", {
      proofBZ.zip(C.map(_._1)).foreach(x => ZeroOrOneBZNIZK.verifyNIZK(pubKey, x._2, x._1))
      UVSumNIZK.verifyNIZK(pubKey, C.map(_._1), sumNIZK)
    })
    println("BZ NIZK proof size: " +
      ((proofBZ.head.A.c1.bytes.length*4 + proofBZ.head.f.toByteArray.length*3)*3 +
        sumNIZK.A1.bytes.size*2 + sumNIZK.z.toByteArray.size) + " bytes")

    println

    TimeUtils.accurate_time("SigmaOR NIZK creation for expert ballot (3 ciphertexts): ", {
      C.foreach(c => ZeroOrOneSigmaNIZK.produceNIZK(pubKey, 1, c._1, c._2).get)
      UVSumNIZK.produceNIZK(pubKey, C).get
    })
    val proofSigma = C.map(c => ZeroOrOneSigmaNIZK.produceNIZK(pubKey, 1, c._1, c._2).get)
    TimeUtils.accurate_time("SigmaOR NIZK verification for expert ballot (3 ciphertexts): ", {
      proofSigma.zip(C.map(_._1)).foreach(x => ZeroOrOneSigmaNIZK.verifyNIZK(pubKey, x._2, x._1))
      UVSumNIZK.verifyNIZK(pubKey, C.map(_._1), sumNIZK)
    })
    println("SigmaOR NIZK proof size: " +
      ((proofBZ.head.A.c1.bytes.length*4 + proofBZ.head.f.toByteArray.length*3)*3 +
        sumNIZK.A1.bytes.size*2 + sumNIZK.z.toByteArray.size) + " bytes")

    println

    TimeUtils.accurate_time("SHV NIZK creation for expert ballot (3 ciphertexts): ", {
      new SHVZKGen(crs, pubKey, C.map(_._1), 0, C.map(_._2)).produceNIZK.get
    })
    val shvzkProof = new SHVZKGen(crs, pubKey, C.map(_._1), 0, C.map(_._2)).produceNIZK.get
    TimeUtils.accurate_time("SHV NIZK verification for expert ballot (3 ciphertexts): ", {
      new SHVZKVerifier(crs, pubKey, C.map(_._1), shvzkProof).verifyProof
    })
    val proofsize: Int =
      shvzkProof.R.toByteArray.size +
      shvzkProof.zwv.size * shvzkProof.zwv(0)._1.toByteArray.size * 3 +
      shvzkProof.Dk.size * shvzkProof.Dk(0).bytes.size +
      shvzkProof.IBA.size * shvzkProof.IBA(0)._1.bytes.size * 3
    println("SHV NIZK proof size: " + proofsize + " bytes")
  }
}

object ExpertBallotPerformance {
  def main(args: Array[String]): Unit = {
    new ExpertBallotPerformance().run
  }
}