package io.iohk.protocol.keygen_2_0.NIZKs

import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.keygen_2_0.NIZKs.CorrectCiphertextsMappingBatched.{Challenge, Commitment, CommitmentParams, Proof, Response, Statement, Witness}
import io.iohk.protocol.keygen_2_0.dlog_encryption.{DLogCiphertext, DLogRandomness}
import io.iohk.protocol.keygen_2_0.math.Polynomial

case class CorrectCiphertextsMappingBatched(pubKeysFrom: Seq[PubKey],
                                            pubKeyTo:    PubKey,
                                            statement:   Statement,
                                            dlogGroup:   DiscreteLogGroup) {
  private val g = dlogGroup.groupGenerator
  private val n = dlogGroup.groupOrder

  private val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  private val lambdas = statement.ctsFrom.zip(statement.ctsTo).map{
    ctFrom_ctTo =>
      val (ctFrom, ctTo) = ctFrom_ctTo
      BigInt(1,
        sha.hash(
          ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
          ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes) ++
          ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
          ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes)
        )
      ).mod(n)
  }

  private def div(g1: GroupElement, g2: GroupElement): GroupElement = {
    dlogGroup.divide(g1, g2).get
  }

  private def mul(g1: GroupElement, g2: GroupElement): GroupElement = {
    dlogGroup.multiply(g1, g2).get
  }

  private def exp(base: GroupElement, exponent: BigInt): GroupElement = {
    dlogGroup.exponentiate(base, exponent).get
  }

  private def combine(scalars: Seq[BigInt], lambda: BigInt): BigInt = {
    Polynomial(dlogGroup, scalars.length, BigInt(0), scalars).evaluate(lambda)
  }

  private def combine(elements: Seq[GroupElement], lambda: BigInt): GroupElement = {
    elements.zipWithIndex.foldLeft(dlogGroup.groupIdentity){
      (result, element_index) =>
        val (element, i) = element_index
        mul(result, exp(element, lambda.pow(i + 1).mod(n)))
    }
  }

  def getCommitmentParams(): CommitmentParams = {
    CommitmentParams(
      for(_ <- pubKeysFrom.indices) yield (dlogGroup.createRandomNumber, dlogGroup.createRandomNumber) // wv
    )
  }

  def getCommitment(params: CommitmentParams): Commitment = {
    Commitment(
      params.wv.foldLeft(dlogGroup.groupIdentity){  // A1 = mul(g^{wm-vm})
        (product, wv) =>
          val (w, v) = wv
          mul(product, div(exp(g, w), exp(g, v)))
      },
      pubKeysFrom.zip(params.wv).map{
        (pk_wv) =>
          val (pk, wv) = pk_wv
          val (w, v) = wv
          div(exp(pk, w), exp(pubKeyTo, v))         // A2m = hm^w / F^v
      }
    )
  }

  def getChallenge(): Challenge = {
    Challenge(
      dlogGroup.createRandomNumber
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge): Response = {

    // In the A2 related part separate proofs for each ciphertext are due to different public keys used for ctsFrom
    val YX = witness.randomnessesFrom.zip(witness.randomnessesTo).zip(lambdas).map{  // sequence of (Xm, Ym, lambda_m)
      rFrom_rTo_lambda =>
        val ((rFrom, rTo), lambda) = rFrom_rTo_lambda
        (combine(rFrom.R, lambda),
         combine(rTo.R, lambda))
    }

    Response(
      params.wv.zip(YX).map{
        wv_YX =>
          val ((w, v), (_Y, _X)) = wv_YX
          ((w + _Y * challenge.e).mod(n),    // v1 = wm + Ym * e
           (v + _X * challenge.e).mod(n))    // v2 = vm + Xm * e
      }
    )
  }

  def prove(witness: Witness): Proof = {
    val params = getCommitmentParams()
    val challenge = getChallenge()
    Proof(
      getCommitment(params),
      challenge,
      getResponse(params, witness, challenge)
    )
  }

  def verify(proof: Proof): Boolean = {

    // A1 related part
    def condition1: Boolean = {

      // ((ctsFrom, ctsTo), lambdas)
      val ctsFrom_ctsTo_lambdas = statement.ctsFrom.zip(statement.ctsTo).zip(lambdas)

      // C1 = mul(ctFrom.c1); R1 = mul(ctTo.c1)
      val (_C1, _R1) = ctsFrom_ctsTo_lambdas.foldLeft((dlogGroup.groupIdentity, dlogGroup.groupIdentity)){
        (product, ctFrom_ctTo_lambda) =>
          val ((ctFrom, ctTo), lambda) = ctFrom_ctTo_lambda
          (mul(product._1, combine(ctFrom.C.map(_.c1), lambda)),
           mul(product._2, combine(ctTo.C.map(_.c1), lambda)))
      }

      val left = mul(
        proof.commitment.A1,
        exp(
          div(_C1, _R1),
          proof.challenge.e
        )
      )

      val (_V1, _V2) = proof.response.v1v2.foldLeft((BigInt(0), BigInt(0))){
        (sum, v1v2) =>
          val (v1, v2) = v1v2
          ((sum._1 + v1).mod(n),    // sum(v1)
            (sum._2 + v2).mod(n))    // sum(v2)
      }

      val right = div(
        exp(g, _V1), // g^sum(v1)
        exp(g, _V2)  // g^sum(v2)
      )

      left == right
    }

    // A2 related part
    def condition2(i: Int) : Boolean = {

      val C2 = combine(statement.ctsFrom(i).C.map(_.c2), lambdas(i))
      val R2 = combine(statement.ctsTo(i).C.map(_.c2), lambdas(i))

      val left = mul(
        proof.commitment.A2(i),
        exp(
          div(C2, R2),
          proof.challenge.e
        )
      )

      val right = div(
        exp(pubKeysFrom(i), proof.response.v1v2(i)._1), // hm^v1
        exp(pubKeyTo, proof.response.v1v2(i)._2)        // F^v2
      )

      left == right
    }

    condition1 && pubKeysFrom.indices.forall(condition2)
  }
}

object CorrectCiphertextsMappingBatched{
  case class CommitmentParams(wv: Seq[(BigInt, BigInt)])
  case class Commitment(A1: GroupElement, A2: Seq[GroupElement])
  case class Challenge(e: BigInt)
  case class Response(v1v2: Seq[(BigInt, BigInt)])

  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)
  case class Witness(randomnessesFrom: Seq[DLogRandomness], randomnessesTo: Seq[DLogRandomness])

  case class Statement(ctsFrom: Seq[DLogCiphertext], ctsTo: Seq[DLogCiphertext])
}
