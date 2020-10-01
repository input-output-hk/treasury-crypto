package io.iohk.protocol.keygen_2_0.NIZKs

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.keygen_2_0.NIZKs.CorrectEncryption._
import io.iohk.protocol.keygen_2_0.dlog_encryption.{DLogCiphertext, DLogRandomness}
import io.iohk.protocol.keygen_2_0.encoding.BaseCodec

case class CorrectEncryption(ct: DLogCiphertext, pubKey: PubKey, dlogGroup: DiscreteLogGroup) {

  private val k = ct.C.size // number of message fragments
  private val g = dlogGroup.groupGenerator
  private val n = dlogGroup.groupOrder

  def getCommitmentParams(): CommitmentParams = {
    CommitmentParams(
      for(_ <- 0 until k) yield dlogGroup.createRandomGroupElement.get,
      for(_ <- 0 until k) yield dlogGroup.createRandomNumber
    )
  }

  def getCommitment(params: CommitmentParams): Commitment = {
    Commitment(
      params.t.map(dlogGroup.exponentiate(g, _).get),
      params.s.zip(params.t).map{ s_t =>
          val (s, t) = s_t
          dlogGroup.multiply(s, dlogGroup.exponentiate(pubKey, t).get).get
      }
    )
  }

  def getChallenge(): Challenge = {
    Challenge(
      for(_ <- 0 until k) yield dlogGroup.createRandomNumber
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, ch: Challenge): Response = {

    val Z1 = params.s.zip(witness.liftedEncodedMsg).zip(ch.e).map{
      s_gm_e =>
        val (s_gm, e) = s_gm_e
        val (s, gm) = s_gm
        dlogGroup.multiply(s, dlogGroup.exponentiate(gm, e).get).get
    }

    val Z2 = params.t.zip(witness.r.R).zip(ch.e).map{
      t_r_e =>
        val (t_r, e) = t_r_e
        val (t, r) = t_r
        (t + r * e).mod(n)
    }
    Response(Z1, Z2)
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

    def condition1(i: Int): Boolean = {
      val E1 = proof.commitment.E1(i)
      val C1 = ct.C(i).c1
      val e = proof.challenge.e(i)
      val Z2 = proof.response.Z2(i)

      dlogGroup.multiply(E1, dlogGroup.exponentiate(C1, e).get).get == dlogGroup.exponentiate(g, Z2).get
    }

    def condition2(i: Int): Boolean = {
      val E2 = proof.commitment.E2(i)
      val C2 = ct.C(i).c2
      val e = proof.challenge.e(i)
      val Z1 = proof.response.Z1(i)
      val Z2 = proof.response.Z2(i)

      dlogGroup.multiply(E2, dlogGroup.exponentiate(C2, e).get).get == dlogGroup.multiply(Z1, dlogGroup.exponentiate(pubKey, Z2).get).get
    }

    val results = for(i <- 0 until k) yield {condition1(i) && condition2(i)}
    results.forall(_ == true)
  }
}

object CorrectEncryption {
  case class CommitmentParams(s: Seq[GroupElement], t: Seq[BigInt])
  case class Commitment(E1: Seq[GroupElement], E2: Seq[GroupElement])
  case class Challenge(e: Seq[BigInt])
  case class Response(Z1: Seq[GroupElement], Z2: Seq[BigInt])

  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)
  case class Witness(msg: BigInt, r: DLogRandomness, dlogGroup: DiscreteLogGroup){
    val liftedEncodedMsg: Seq[GroupElement] = BaseCodec.encode(msg).seq.map(dlogGroup.exponentiate(dlogGroup.groupGenerator, _).get)
  }
}
