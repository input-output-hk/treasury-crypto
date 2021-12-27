package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{_}
import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectSecret.{Challenge, Commitment, CommitmentParams, Proof, Response, Statement, Witness}

case class CorrectSecret(crs:   GroupElement,       // base for commitment of the G(x) coefficients [C0,.. Ct-1]
                         mfCt:  ElGamalCiphertext,  // encryption of a secret value mf, which is a constant coefficient of F(x)
                         group: DiscreteLogGroup){

  private val g = group.groupGenerator
  private val n = group.groupOrder

  private val E1 = mfCt.c1
  private val E2 = mfCt.c2

  def getCommitmentParams: CommitmentParams = {
    CommitmentParams(
      group.createRandomNumber,
      group.createRandomNumber
    )
  }

  def getCommitment(params: CommitmentParams)
                   (implicit dlogGroup: DiscreteLogGroup): Commitment = {
    Commitment(
      a1 = exp(g, params.p1),
      a2 = mul(
        inv(exp(E1, params.p1)),
        exp(crs, params.p2)
      )
    )
  }

  def getChallenge: Challenge = {
    Challenge(
      group.createRandomNumber
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge): Response = {
    Response(
      z1 = (params.p1 + witness.privKey * challenge.e).mod(n),
      z2 = (params.p2 + witness.C0 * challenge.e).mod(n)
    )
  }

  def prove(witness: Witness)
           (implicit dlogGroup: DiscreteLogGroup): Proof = {
    val params = getCommitmentParams
    val challenge = getChallenge
    Proof(
      getCommitment(params),
      challenge,
      getResponse(params, witness, challenge)
    )
  }

  def verify(proof: Proof, st: Statement)
            (implicit dlogGroup: DiscreteLogGroup): Boolean = {

    def condition1: Boolean = {
      val left = mul(
        inv(exp(E1, proof.response.z1)),
        exp(crs, proof.response.z2)
      )

      val right = mul(
        exp(div(st.D0, E2), proof.challenge.e),
        proof.commitment.a2
      )

      left == right
    }

    def condition2: Boolean = {
      val left = exp(g, proof.response.z1)

      val right = mul(
        exp(st.pubKey, proof.challenge.e),
        proof.commitment.a1)

      left == right
    }

    condition1 && condition2
  }
}

object CorrectSecret {
  case class CommitmentParams(p1: BigInt, p2: BigInt)
  case class Commitment(a1: GroupElement, a2: GroupElement)
  case class Challenge(e: BigInt)
  case class Response(z1: BigInt, z2: BigInt)

  case class Witness(privKey: PrivKey, C0: BigInt)
  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)

  case class Statement(pubKey: PubKey,       // public key that was used to encrypt mf into mfCt
                       D0:     GroupElement) // commitment (Sigma in specification) D0 = g^F(0) * crs^G(0) = g^mf * crs^C0
}
