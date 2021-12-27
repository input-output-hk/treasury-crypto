package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.common.dlog_encryption.{DLogCiphertext, DLogRandomness}
import io.iohk.protocol.common.encoding.BaseCodec
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.utils.DlogGroupArithmetics._
import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectEncryption.{Challenge, Commitment, CommitmentParams, Proof, Response, Witness}

// Sequence of ElGamal ciphertexts encrypted on the same public key
case class CorrectEncryption(cts: Seq[DLogCiphertext], pubKey: PubKey, dlogGroup: DiscreteLogGroup) {

  private val g = dlogGroup.groupGenerator
  private val n = dlogGroup.groupOrder

  private val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  private val lambdas = cts.map{
    ct =>
      BigInt(1,
        sha.hash(
          ct.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
          ct.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes)
        )
      ).mod(n)
  }

  private def combine(scalars: Seq[BigInt], lambda: BigInt): BigInt = {
    Polynomial(dlogGroup, scalars.length, BigInt(0), scalars).evaluate(lambda)
  }

  private def combine(elements: Seq[GroupElement], lambda: BigInt)
                     (implicit dlogGroup: DiscreteLogGroup): GroupElement = {
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

  def getCommitment(params: CommitmentParams)
                   (implicit dlogGroup: DiscreteLogGroup): Commitment = {
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

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge)
                 (implicit dlogGroup: DiscreteLogGroup): Response = {
    val g_D = witness.liftedEncodedMsgs.zip(lambdas).foldLeft(dlogGroup.groupIdentity){
      (product, liftedEncodedMsg_lambda) =>
        val (liftedEncodedMsg, lambda) = liftedEncodedMsg_lambda
        mul(product, combine(liftedEncodedMsg, lambda))
    }
    val X = witness.rs.zip(lambdas).foldLeft(BigInt(0)){
      (sum, r_lambda) =>
        val (r, lambda) = r_lambda
        sum + combine(r.R, lambda)
    }

    Response(
      mul(params.s, exp(g_D, challenge.e)),  // alpha
      (params.t + X * challenge.e).mod(n)    // beta
    )
  }

  def prove(w: Witness)
           (implicit dlogGroup: DiscreteLogGroup): Proof = {
    val params = getCommitmentParams()
    val challenge = getChallenge()
    Proof(
      getCommitment(params),
      challenge,
      getResponse(params, w, challenge)
    )
  }

  def verify(proof: Proof)
            (implicit dlogGroup: DiscreteLogGroup): Boolean = {
    val E1 = proof.commitment.E1
    val E2 = proof.commitment.E2
    val e = proof.challenge.e
    val alpha = proof.response.alpha
    val beta = proof.response.beta

    val R = cts.zip(lambdas).foldLeft((dlogGroup.groupIdentity, dlogGroup.groupIdentity)){
      (product, ct_lambda) =>
        val (ct, lambda) = ct_lambda
        (mul(product._1, combine(ct.C.map(_.c1), lambda)),
         mul(product._2, combine(ct.C.map(_.c2), lambda)))
    }

    val condition1 = {
      mul(E1, exp(R._1, e)) == exp(g, beta)
    }

    val condition2 = {
      mul(E2, exp(R._2, e)) == mul(alpha, exp(pubKey, beta))
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
  case class Witness(msgs: Seq[BigInt], rs: Seq[DLogRandomness], dlogGroup: DiscreteLogGroup){
    val liftedEncodedMsgs: Seq[Seq[GroupElement]] = msgs.map{ msg =>
      BaseCodec.encode(msg).seq.map(dlogGroup.exponentiate(dlogGroup.groupGenerator, _).get)
    }
  }
}
