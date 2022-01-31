package io.iohk.protocol.voting_2_0.preferential

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.ZeroOrOne
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.ZeroOrOne.{Statement, Witness}
import io.iohk.protocol.voting_2_0.preferential.BallotVoter.sumEncryptedUVsAndRand

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

// Number of ranking vectors corresponds to a shortlist length (position in a shortlist per vector);
// Length of each ranking vector corresponds to a total number of projects
case class BallotExpert(rankingVectors:      Seq[Seq[ElGamalCiphertext]],
                        unitVectorsProofs:   Seq[SHVZKProof],
                        rankingVectorsProof: ZeroOrOneNIZK.datastructures.Proof
                      ) extends HasSize {
  // All ranking vectors should have the same size
  assert(rankingVectors.nonEmpty && rankingVectors.forall(_.size == rankingVectors.head.size))
  def size: Int = {
      rankingVectors.foldLeft(0)((totalSize, elems) => totalSize + elems.foldLeft(0)((totalSize, elem) => totalSize + elem.bytes.length)) +
      unitVectorsProofs.foldLeft(0)((totalSize, proof) => totalSize + proof.bytes.length) +
      rankingVectorsProof.bytes.length
  }
}

object BallotExpert {

  def cast(pubKey: PubKey,
           params: VotingParameters,
           ranks: Seq[Int]): Try[BallotExpert] = Try{
    import params.cryptoContext.{group, hash, commonReferenceString}
    import params.{shortlistSize, projectsNum, expertsNum}

    // Building unit vectors by specified parameters
    val rankingUVs = {
      assert(ranks.length == shortlistSize)
      ranks.map{projectId =>
        assert(projectId >= 0 && projectId < projectsNum) // Project IDs supposed to be [0, 1,..., shortlistSize - 1]
        val rankVec = ArrayBuffer.fill[BigInt](projectsNum - 1)(BigInt(0))
        rankVec.insert(projectId, BigInt(1)) // setting 1 in position corresponding the project ID
        rankVec
      }
    }

    // Encrypting binary ranking vectors
    val encRankingUVs = rankingUVs.map(_.map(LiftedElGamalEnc.encrypt(pubKey, _).get))
    // Element-wise sum of encrypted ranking UVs
    val encRankingUVsSum = sumEncryptedUVsAndRand(encRankingUVs)

    val st = Statement(pubKey, encRankingUVsSum.map(_._1))
    val w = Witness(
      rankingUVs.transpose.map(_.sum), // element-wise sum of plain ranking UVs
      encRankingUVsSum.map(_._2)       // summed randomnesses
    )

    val proofForRankingUVsSum = ZeroOrOne(st).prove(w)
//    assert(ZeroOrOne(st).verify(proofForRankingUVsSum)) // TODO: comment for benchmarking

    val proofsForUVs = encRankingUVs.zip(ranks).map{
      case (encRankingUV, uvIndex) =>
        val proof = new SHVZKGen(commonReferenceString, pubKey,
          encRankingUV.map(_._1),
          uvIndex, // index corresponding to the ranking UV
          encRankingUV.map(_._2)
        ).produceNIZK().get

//        assert(new SHVZKVerifier(commonReferenceString, pubKey, encRankingUV.map(_._1), proof)
//          .verifyProof()
//        ) // TODO: comment for benchmarking
        proof
    }
    BallotExpert(encRankingUVs.map(_.map(_._1)), proofsForUVs, proofForRankingUVsSum)
  }
}
