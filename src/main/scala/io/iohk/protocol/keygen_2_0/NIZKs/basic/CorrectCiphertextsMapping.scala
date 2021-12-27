package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.common.dlog_encryption.{DLogCiphertext, DLogRandomness}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{_}
import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectCiphertextsMapping.{Challenge, Commitment, CommitmentParams, Proof, Response, Statement, Witness}
import io.iohk.protocol.keygen_2_0.NIZKs.utils.Combining.combine

case class CorrectCiphertextsMapping(pubKeyFrom: PubKey,
                                     pubKeyTo:   PubKey,
                                     statement:  Statement,
                                     dlogGroup:  DiscreteLogGroup) {
  private val g = dlogGroup.groupGenerator
  private val n = dlogGroup.groupOrder

  private val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  private val lambda = BigInt(1,
    sha.hash(
      statement.ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
      statement.ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes) ++
      statement.ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
      statement.ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes)
    )
  ).mod(n)

  def getCommitmentParams(): CommitmentParams = {
    CommitmentParams(
      dlogGroup.createRandomNumber, // w
      dlogGroup.createRandomNumber  // v
    )
  }

  def getCommitment(params: CommitmentParams)
                   (implicit dlogGroup: DiscreteLogGroup): Commitment = {
    Commitment(
      div(                           // A1 = g^{w-v}
        exp(g, params.w),
        exp(g, params.v)
      ),
      div(                           // A2 = h^w / F^v
        exp(pubKeyFrom, params.w),
        exp(pubKeyTo,   params.v)
      )
    )
  }

  def getChallenge(): Challenge = {
    Challenge(
      dlogGroup.createRandomNumber
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge)
                 (implicit dlogGroup: DiscreteLogGroup): Response = {
    val Y = combine(witness.randomnessFrom.R, lambda)
    val X = combine(witness.randomnessTo.R, lambda)

    Response(
      (params.w + Y * challenge.e).mod(n), // v1
      (params.v + X * challenge.e).mod(n)  // v2
    )
  }

  def prove(witness: Witness)
           (implicit dlogGroup: DiscreteLogGroup): Proof = {
    val params = getCommitmentParams()
    val challenge = getChallenge()
    Proof(
      getCommitment(params),
      challenge,
      getResponse(params, witness, challenge)
    )
  }

  def verify(proof: Proof)
            (implicit dlogGroup: DiscreteLogGroup): Boolean = {
    def condition1: Boolean = {
      val C1 = combine(statement.ctFrom.C.map(_.c1), lambda)
      val R1 = combine(statement.ctTo.C.map(_.c1), lambda)

      val left = mul(
        proof.commitment.A1,
        exp(div(C1, R1), proof.challenge.e)
      )

      val right = div(
        exp(g, proof.response.v1),
        exp(g, proof.response.v2)
      )

      left == right
    }

    def condition2: Boolean = {
      val C2 = combine(statement.ctFrom.C.map(_.c2), lambda)
      val R2 = combine(statement.ctTo.C.map(_.c2), lambda)

      val left = mul(
        proof.commitment.A2,
        exp(div(C2, R2), proof.challenge.e)
      )

      val right = div(
        exp(pubKeyFrom, proof.response.v1),
        exp(pubKeyTo, proof.response.v2)
      )

      left == right
    }

    condition1 && condition2
  }
}

object CorrectCiphertextsMapping{
  case class CommitmentParams(w: BigInt, v: BigInt)
  case class Commitment(A1: GroupElement, A2: GroupElement)
  case class Challenge(e: BigInt)
  case class Response(v1: BigInt, v2: BigInt)

  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)
  case class Witness(randomnessFrom: DLogRandomness, randomnessTo: DLogRandomness)

  case class Statement(ctFrom: DLogCiphertext, ctTo: DLogCiphertext)
}
