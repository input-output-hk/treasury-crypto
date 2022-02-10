package io.iohk.protocol.voting_2_0.preferential

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.shvzk.SHVZKVerifier
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.BatchedZeroOrOne.Statement
import org.scalatest.FunSuite

import scala.util.Try

class BallotTests extends FunSuite {
  private val context = new CryptoContext(None)

  val (secretKey, pubKey) = encryption.createKeyPair(context.group).get
  import context.{group, hash, commonReferenceString}

  def checkVotersBallots(ballots: Seq[BallotVoter])
                        (implicit group: DiscreteLogGroup): Boolean = Try{
    ballots.forall{ballot =>
      val st = Statement(pubKey, BallotVoter.sumEncryptedUVs(ballot.rankingVectors))
      val rankingVectorsAreValid = BatchedZeroOrOne(st).verify(ballot.rankingVectorsProof)

      assert(ballot.rankingVectors.size == ballot.unitVectorsProofs.size)

      val uvsAreValid = ballot.rankingVectors.zip(ballot.unitVectorsProofs).forall{
        case (rankingVector, uvProof) =>
          new SHVZKVerifier(commonReferenceString, pubKey,
            rankingVector ++ ballot.delegationVector, uvProof).verifyProof()
      }
      uvsAreValid && rankingVectorsAreValid
    }
  }.getOrElse(false)

  def sumVotersBallots(ballots: Seq[BallotVoter])
                      (implicit group: DiscreteLogGroup): (Seq[ElGamalCiphertext], Seq[Seq[ElGamalCiphertext]]) = {
    val delegations = ballots.map(_.delegationVector)
    val rankings = ballots.map(_.rankingVectors)
    (BallotVoter.sumEncryptedUVs(delegations), rankings.transpose.map(BallotVoter.sumEncryptedUVs))
  }

  def checkExpertsBallots(ballots: Seq[BallotExpert])
                         (implicit group: DiscreteLogGroup): Boolean = Try{
    ballots.forall{ballot =>
      val st = Statement(pubKey, BallotVoter.sumEncryptedUVs(ballot.rankingVectors))
      val rankingVectorsAreValid = BatchedZeroOrOne(st).verify(ballot.rankingVectorsProof)

      assert(ballot.rankingVectors.size == ballot.unitVectorsProofs.size)

      val uvsAreValid = ballot.rankingVectors.zip(ballot.unitVectorsProofs).forall{
        case (rankingVector, uvProof) =>
          new SHVZKVerifier(commonReferenceString, pubKey,
            rankingVector, uvProof).verifyProof()
      }
      uvsAreValid && rankingVectorsAreValid
    }
  }.getOrElse(false)

  def sumExpertsBallots(ballots: Seq[BallotExpert])
                       (implicit group: DiscreteLogGroup): Seq[Seq[ElGamalCiphertext]] = {
    val rankings = ballots.map(_.rankingVectors)
    rankings.transpose.map(BallotVoter.sumEncryptedUVs)
  }

  def decryptUV(uv: Seq[ElGamalCiphertext]): Try[Seq[BigInt]] = Try{
    uv.map(LiftedElGamalEnc.decrypt(secretKey, _).get)
  }

  test("BallotVoterTests"){
    val shortlistSize = 4
    val projectsNum = 8
    val expertsNum = 8

    val params = VotingParameters(context, shortlistSize, projectsNum, expertsNum)

    assert(BallotVoter.cast(pubKey, params, Left(Seq(0, 2, 4))).isFailure)              // insufficient shortlist length
    assert(BallotVoter.cast(pubKey, params, Left(Seq(0, 2, 4, 6, 7))).isFailure)        // excessive shortlist length
    assert(BallotVoter.cast(pubKey, params, Right(expertsNum)).isFailure)               // incorrect expert ID
    assert(BallotVoter.cast(pubKey, params, Left(Seq(0, 2, 4, projectsNum))).isFailure) // incorrect project ID

    val ballot0 = BallotVoter.cast(pubKey, params, Right(3))
    val ballot1 = BallotVoter.cast(pubKey, params, Right(7))
    val ballot2 = BallotVoter.cast(pubKey, params, Left(Seq(0, 2, 4, 6)))
    val ballot3 = BallotVoter.cast(pubKey, params, Left(Seq(0, 2, 4, 6)))
    assert(ballot0.isSuccess && ballot1.isSuccess && ballot2.isSuccess && ballot3.isSuccess)

    val ballots = Seq(ballot0.get, ballot1.get, ballot2.get, ballot3.get)

    assert(checkVotersBallots(ballots))

    val (delegationsSumEnc, rankingsSumEnc) = sumVotersBallots(ballots)
    val delegationsSum = decryptUV(delegationsSumEnc).get
    val rankingsSum = rankingsSumEnc.map(decryptUV(_).get)
    assert(delegationsSum.map(_.toLong) == Seq(0, 0, 0, 1, 0, 0, 0, 1))
    assert(rankingsSum.map(_.map(_.toLong)) == Seq(
      Seq(2, 0, 0, 0, 0, 0, 0, 0),
      Seq(0, 0, 2, 0, 0, 0, 0, 0),
      Seq(0, 0, 0, 0, 2, 0, 0, 0),
      Seq(0, 0, 0, 0, 0, 0, 2, 0)
    ))
  }

  test("BallotExpertTests"){
    val shortlistSize = 4
    val projectsNum = 8
    val expertsNum = 4

    val params = VotingParameters(context, shortlistSize, projectsNum, expertsNum)

    assert(BallotExpert.cast(pubKey, params, Seq(0, 2, 4)).isFailure)              // insufficient shortlist length
    assert(BallotExpert.cast(pubKey, params, Seq(0, 2, 4, 6, 7)).isFailure)        // excessive shortlist length

    val ballot0 = BallotExpert.cast(pubKey, params, Seq(0, 2, 4, 6))
    val ballot1 = BallotExpert.cast(pubKey, params, Seq(0, 2, 4, 6))
    val ballot2 = BallotExpert.cast(pubKey, params, Seq(1, 3, 5, 7))
    val ballot3 = BallotExpert.cast(pubKey, params, Seq(1, 3, 5, 7))
    assert(ballot0.isSuccess && ballot1.isSuccess && ballot2.isSuccess && ballot3.isSuccess)

    val ballots = Seq(ballot0.get, ballot1.get, ballot2.get, ballot3.get)

    assert(checkExpertsBallots(ballots))

    val rankingsSumEnc = sumExpertsBallots(ballots)
    val rankingsSum = rankingsSumEnc.map(decryptUV(_).get)
    assert(rankingsSum.map(_.map(_.toLong)) == Seq(
      Seq(2, 2, 0, 0, 0, 0, 0, 0),
      Seq(0, 0, 2, 2, 0, 0, 0, 0),
      Seq(0, 0, 0, 0, 2, 2, 0, 0),
      Seq(0, 0, 0, 0, 0, 0, 2, 2)
    ))
  }
}
