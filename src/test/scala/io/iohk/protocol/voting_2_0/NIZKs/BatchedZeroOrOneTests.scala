package io.iohk.protocol.voting_2_0.NIZKs

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.utils.Serialization.serializationIsCorrect
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne.{Statement, Witness}
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.datastructures.ProofSerializer
import io.iohk.protocol.voting_2_0.preferential.BallotVoter.sumEncryptedUVsAndRand
import org.scalatest.FunSuite

import scala.util.Random

class BatchedZeroOrOneTests extends FunSuite {
  private val context = new CryptoContext(None)

  import context.group

  test("BatchedZeroOrOneTests"){
    val vecSize = 200
    val pubKey = encryption.createKeyPair(context.group).get._2

    val binaryVec = (0 until vecSize).map(_ => BigInt(Random.nextInt(2))) // random binary vector
    val encBinaryVec = binaryVec.map(LiftedElGamalEnc.encrypt(pubKey, _).get)

    val st = Statement(pubKey, encBinaryVec.map(_._1))
    val w = Witness(binaryVec, encBinaryVec.map(_._2))

    val proof = BatchedZeroOrOne(st).prove(w)
    assert(serializationIsCorrect(Seq(proof), ProofSerializer))
    assert(BatchedZeroOrOne(st).verify(proof))
  }

  test("ZeroOrOneMultivec"){
    val vecNum = 20
    val vecSize = 20

    val pubKey = encryption.createKeyPair(context.group).get._2

    val binaryVecs = (0 until vecNum).map{
      i =>
        (0 until vecSize)map{
          j =>
            BigInt(if (i == j) Random.nextInt(2) else 0) // matrix of all zeroes except for randomized diagonal (0 or 1)
      }
    }
    // Element-wise sum of binary vectors
    val binaryVecsSum = binaryVecs.transpose.map(_.sum) // transpose to go through elements at the same position in vectors

    // Encrypting binary vectors
    val encBinaryVecs = binaryVecs.map(_.map(LiftedElGamalEnc.encrypt(pubKey, _).get))
    // Element-wise sum of encrypted binary vectors
    val encBinaryVecsSum = sumEncryptedUVsAndRand(encBinaryVecs)

    val st = Statement(pubKey, encBinaryVecsSum.map(_._1))
    val w = Witness(binaryVecsSum, encBinaryVecsSum.map(_._2))

    val proof = BatchedZeroOrOne(st).prove(w)
    assert(serializationIsCorrect(Seq(proof), ProofSerializer))
    assert(BatchedZeroOrOne(st).verify(proof))
  }
}
