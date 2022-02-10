package io.iohk.protocol.voting_2_0.preferential

import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.utils.HasSize
import io.iohk.protocol.common.utils.DlogGroupArithmetics.mul
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne.{Statement, Witness}

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

// Number of ranking vectors corresponds to a shortlist length (position in a shortlist per vector);
// Length of each ranking vector corresponds to a total number of projects
case class BallotVoter(delegationVector:    Seq[ElGamalCiphertext],
                       rankingVectors:      Seq[Seq[ElGamalCiphertext]],
                       unitVectorsProofs:   Seq[SHVZKProof],
                       rankingVectorsProof: ZeroOrOneNIZK.datastructures.Proof
                      ) extends HasSize {
  // All ranking vectors should have the same size
  assert(rankingVectors.nonEmpty && rankingVectors.forall(_.size == rankingVectors.head.size))
  def size: Int = {
    delegationVector.foldLeft(0)((totalSize, elem) => totalSize + elem.bytes.length) +
      rankingVectors.foldLeft(0)((totalSize, elems) => totalSize + elems.foldLeft(0)((totalSize, elem) => totalSize + elem.bytes.length)) +
      unitVectorsProofs.foldLeft(0)((totalSize, proof) => totalSize + proof.bytes.length) +
      rankingVectorsProof.bytes.length
  }
}

object BallotVoter {

  def sumEncryptedUVsAndRand(encRankingUVs: Seq[Seq[(ElGamalCiphertext, Randomness)]])
                            (implicit dlogGroup: DiscreteLogGroup): Seq[(ElGamalCiphertext, Randomness)] = {
    // All UV's are of the same length
    assert(encRankingUVs.nonEmpty && encRankingUVs.forall(_.size == encRankingUVs.head.size))

    encRankingUVs.transpose.map(vec => // transpose to go through encrypted elements at the same position in vectors
      vec.reduce(
        (c_r_sum, c_r) =>
          (
            ElGamalCiphertext(
              mul(c_r_sum._1.c1, c_r._1.c1), mul(c_r_sum._1.c2, c_r._1.c2) // (c1 * c1_, c2 * c2_)
            ),
            c_r_sum._2 + c_r._2 // randomness is also summed
          )
      )
    )
  }

  def sumEncryptedUVs(encRankingUVs: Seq[Seq[ElGamalCiphertext]])
                     (implicit dlogGroup: DiscreteLogGroup): Seq[ElGamalCiphertext] = {
    // All UV's are of the same length
    assert(encRankingUVs.nonEmpty && encRankingUVs.forall(_.size == encRankingUVs.head.size))

    encRankingUVs.transpose.map(vec => // transpose to go through encrypted elements at the same position in vectors
      vec.reduce(
        (c_sum, c) =>
          (
            ElGamalCiphertext(
              mul(c_sum.c1, c.c1), mul(c_sum.c2, c.c2) // (c1 * c1_, c2 * c2_)
            )
          )
      )
    )
  }

  // Project IDs in ranks supposed to be [0, 1,..., shortlistSize - 1]
  def cast(pubKey: PubKey,
           params: VotingParameters,
           ranksOrExpertID: Either[Seq[Int], Int]): Try[BallotVoter] = Try {

    import params.cryptoContext.{group, hash, commonReferenceString}
    import params.{shortlistSize, projectsNum, expertsNum}

    // Building unit vectors by specified parameters
    val (rankingUVs, delegationUV) = ranksOrExpertID match {
      case Left(ranks) => {
        assert(ranks.length == shortlistSize)
        val rankVectors = ranks.map{projectId =>
          assert(projectId >= 0 && projectId < projectsNum) // Project IDs supposed to be [0, 1,..., shortlistSize - 1]
          val rankVec = ArrayBuffer.fill[BigInt](projectsNum - 1)(BigInt(0))
          rankVec.insert(projectId, BigInt(1)) // setting 1 in position corresponding the project ID
          rankVec
        }
        val emptyDelegationsVector = ArrayBuffer.fill[BigInt](expertsNum)(BigInt(0))
        (rankVectors, emptyDelegationsVector)
      }
      case Right(expertID) => {
        val emptyRanks = (0 until shortlistSize).map(_ =>
          (0 until projectsNum).map(_ => BigInt(0))
        )
        assert(expertID >= 0 && expertID < expertsNum) // Experts IDs supposed to be [0, 1,..., expertsNum - 1]
        val delegationsVector = ArrayBuffer.fill[BigInt](expertsNum - 1)(BigInt(0))
        delegationsVector.insert(expertID, BigInt(1)) // setting 1 in position corresponding the expert's ID
        (emptyRanks, delegationsVector)
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

    val proofForRankingUVsSum = BatchedZeroOrOne(st).prove(w)
//    assert(ZeroOrOne(st).verify(proofForRankingUVsSum)) // TODO: comment for benchmarking

    val encDelegationUV = delegationUV.map(LiftedElGamalEnc.encrypt(pubKey, _).get)

    val uvIndexes = ranksOrExpertID match {
      case Left(ranks) => ranks
      case Right(expertID) => ArrayBuffer.fill[Int](shortlistSize)(projectsNum + expertID)
    }

    val proofsForUVs = encRankingUVs.zip(uvIndexes).map{
      case (encRankingUV, uvIndex) =>
        val encRankingAndDelegationUV = encRankingUV.map(_._1) ++ encDelegationUV.map(_._1)
        val encRankingAndDelegationRandomness = encRankingUV.map(_._2) ++ encDelegationUV.map(_._2)
        val proof = new SHVZKGen(commonReferenceString, pubKey,
          encRankingAndDelegationUV,
          uvIndex, // index corresponding to the ranking UV
          encRankingAndDelegationRandomness
        ).produceNIZK().get

//        assert(new SHVZKVerifier(commonReferenceString, pubKey, encRankingAndDelegationUV, proof)
//          .verifyProof()
//        ) // TODO: comment for benchmarking
        proof
    }

    BallotVoter(encDelegationUV.map(_._1), encRankingUVs.map(_.map(_._1)), proofsForUVs, proofForRankingUVsSum)
  }
}
