package io.iohk.protocol.keygen_2_0.NIZKs

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.keygen_2_0.NIZKs.CorrectEncryption._
import io.iohk.protocol.keygen_2_0.dlog_encryption.{DLogCiphertext, DLogRandomness}
import io.iohk.protocol.keygen_2_0.encoding.BaseCodec
import io.iohk.protocol.keygen_2_0.math.Polynomial

case class CorrectEncryption(ct: DLogCiphertext, pubKey: PubKey, dlogGroup: DiscreteLogGroup) {

  private val g = dlogGroup.groupGenerator
  private val n = dlogGroup.groupOrder

  private val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  private val lambda = BigInt(1,
    sha.hash(
      ct.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
      ct.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes)
    )
  ).mod(n)

  private def mul(g1: GroupElement, g2: GroupElement): GroupElement = {
    dlogGroup.multiply(g1, g2).get
  }

  private def exp(base: GroupElement, exponent: BigInt): GroupElement = {
    dlogGroup.exponentiate(base, exponent).get
  }

  private def combine(scalars: Seq[BigInt]): BigInt = {
    Polynomial(dlogGroup, scalars.length, BigInt(0), scalars).evaluate(lambda)
  }

  private def combine(elements: Seq[GroupElement]): GroupElement = {
    elements.zipWithIndex.foldLeft(dlogGroup.groupIdentity){
      (result, element_index) =>
        val (element, i) = element_index
        mul(result, exp(element, lambda.pow(i + 1).mod(n)))
    }
  }

  def getCommitmentParams(): CommitmentParams = {
    CommitmentParams(
      dlogGroup.createRandomGroupElement.get,
      dlogGroup.createRandomNumber
    )
  }

  def getCommitment(params: CommitmentParams): Commitment = {
    Commitment(
      exp(g, params.t),
      mul(params.s, exp(pubKey, params.t))
    )
  }

  def getChallenge(): Challenge = {
    Challenge(
      dlogGroup.createRandomNumber
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge): Response = {
    val g_D = combine(witness.liftedEncodedMsg)
    val X   = combine(witness.r.R)

    Response(
      mul(params.s, exp(g_D, challenge.e)),  // alpha
      (params.t + X * challenge.e).mod(n)    // beta
    )
  }

  def prove(w: Witness): Proof = {
    val params = getCommitmentParams()
    val challenge = getChallenge()
    Proof(
      getCommitment(params),
      challenge,
      getResponse(params, w, challenge)
    )
  }

  def verify(proof: Proof): Boolean = {
    val E1 = proof.commitment.E1
    val E2 = proof.commitment.E2
    val e = proof.challenge.e
    val alpha = proof.response.alpha
    val beta = proof.response.beta

    val condition1 = {
      val R1 = combine(ct.C.map(_.c1))
      mul(E1, exp(R1, e)) == exp(g, beta)
    }

    val condition2 = {
      val R2 = combine(ct.C.map(_.c2))
      mul(E2, exp(R2, e)) == mul(alpha, exp(pubKey, beta))
    }

    condition1 && condition2
  }
}

object CorrectEncryption {
  case class CommitmentParams(s: GroupElement, t: BigInt)
  case class Commitment(E1: GroupElement, E2: GroupElement)
  case class Challenge(e: BigInt)
  case class Response(alpha: GroupElement, beta: BigInt)

  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)
  case class Witness(msg: BigInt, r: DLogRandomness, dlogGroup: DiscreteLogGroup){
    val liftedEncodedMsg: Seq[GroupElement] = BaseCodec.encode(msg).seq.map(dlogGroup.exponentiate(dlogGroup.groupGenerator, _).get)
  }
}
