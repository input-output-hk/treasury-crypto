package io.iohk.protocol.keygen_2_0.NIZKs.rnce

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.CorrectSecret.{CRS, Challenge, Commitment, CommitmentParams, Proof, Response, Witness}
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import io.iohk.protocol.keygen_2_0.utils.DlogGroupArithmetics.{div, exp, mul}

case class CorrectSecret(crs:   CRS,
                         implicit val group: DiscreteLogGroup) {
  private val g1 = crs.rnce_crs.g1 // mu
  private val g2 = crs.rnce_crs.g2 // rho
  private val g3 = crs.g3          // eta

  private val modulus = group.groupOrder

  private def randZq = group.createRandomNumber

  def getCommitmentParams: CommitmentParams = {
    CommitmentParams(randZq, randZq, randZq)
  }

  def getCommitment(params: CommitmentParams, witness: Witness): Commitment = {
    val d1 = exp(g1, params.s1)
    val d2 = mul(exp(g2, params.s1), exp(g3, params.s2))
    val d3 = div(d1, d2)

    val F = mul(exp(g1, witness.s), exp(g1, witness.s_))

    // commitment D0 = mu^s * rho^s_ * eta^o_0 - commitment of constant coefficients a0 of three Lagrange polynomials
    val Delta0 = mul(mul(exp(g1, witness.s), exp(g2, witness.s_)), exp(g3, params.o_0))

    Commitment(d1, d2, d3, F, Delta0)
  }

  def getChallenge: Challenge = {
    Challenge(e = randZq)
  }

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge): Response = {
    Response(
      D = (params.s1 + challenge.e * witness.s_) mod modulus,
      E = (params.s2 + challenge.e * params.o_0) mod modulus
    )
  }

  def prove(witness: Witness): Proof = {
    val params = getCommitmentParams
    val challenge = getChallenge
    Proof(
      getCommitment(params, witness),
      challenge,
      getResponse(params, witness, challenge)
    )
  }

  def verify(proof: Proof): Boolean = {
    val left = mul(
      exp(div(proof.commitment.F, proof.commitment.Delta0), proof.challenge.e),
      proof.commitment.d3
    )
    val right = div(
      exp(g1, proof.response.D),
      mul(exp(g2, proof.response.D), exp(g3, proof.response.E))
    )
    left == right
  }
}

object CorrectSecret {

  case class CRS(rnce_crs:  RnceCrsLight,  // g1 = mu, g2 = rho
                 g3:        GroupElement)  // g3 = eta

  case class CommitmentParams(s1: BigInt, s2: BigInt, o_0: BigInt)
  case class Commitment(d1: GroupElement, d2: GroupElement, d3: GroupElement, F: GroupElement, Delta0: GroupElement)
  case class Challenge(e: BigInt)
  case class Response(D: BigInt, E: BigInt)

  // secrets which are intended to be shared
  case class Witness(s: BigInt,   // secret value s
                     s_ : BigInt) // secret value s_

  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)
}
