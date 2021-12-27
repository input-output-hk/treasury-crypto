package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.common.dlog_encryption.DLogCiphertext
import io.iohk.protocol.common.encoding.BaseCodec
import io.iohk.protocol.common.math.LagrangeInterpolation
import io.iohk.protocol.common.utils.DlogGroupArithmetics._
import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectSharing.{Challenge, Commitment, CommitmentParams, Proof, Response, Statement, Witness}

case class CorrectSharing(pubKey: PubKey, dlogGroup: DiscreteLogGroup) {

  private val g = dlogGroup.groupGenerator
  private val n = dlogGroup.groupOrder
  private val identity = dlogGroup.groupIdentity
  private val base = BaseCodec.defaultBase

  def getCommitmentParams(): CommitmentParams = {
    CommitmentParams(
      dlogGroup.createRandomNumber,
      dlogGroup.createRandomNumber,
      dlogGroup.createRandomNumber
    )
  }

  def getCommitment(params: CommitmentParams)
                   (implicit dlogGroup: DiscreteLogGroup): Commitment = {
    Commitment(
      T1 = mul(
        exp(g, params.a),
        exp(pubKey, params.b)
      ),
      T2 = exp(g, params.c),
      T3 = mul(
        exp(g, params.a),
        exp(pubKey, params.c)
      )
    )
  }

  def getChallenge(): Challenge = {
    Challenge(
      dlogGroup.createRandomNumber
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge): Response = {
    Response(
      y1 = (params.a + witness.share * challenge.e).mod(n),
      y2 = (params.b + witness.shareAux * challenge.e).mod(n),
      y3 = (params.c + witness.initialRandomness * challenge.e).mod(n)
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

  def verify(proof: Proof, st: Statement)
            (implicit dlogGroup: DiscreteLogGroup): Boolean = {

    def condition1: Boolean = {
      val left = mul(
        exp(g, proof.response.y1),
        exp(pubKey, proof.response.y2)
      )
      val right = mul(
        exp(st.D, proof.challenge.e),
        proof.commitment.T1
      )

      left == right
    }

    def condition2: Boolean = {
      val W1 = getW1(st.ct.take(st.threshold))// getW1(st.ct) //getW1(st.ct.take(st.threshold))

      val left = exp(g, proof.response.y3)
      val right = mul(
        exp(W1, proof.challenge.e),
        proof.commitment.T2
      )

      left == right
    }

    def condition3: Boolean = {
      val W2 = getW2(st.ct.take(st.threshold))// getW2(st.ct) //getW2(st.ct.take(st.threshold))

      val left = mul(
        exp(g, proof.response.y1),
        exp(pubKey, proof.response.y3)
      )
      val right = mul(
        exp(W2, proof.challenge.e),
        proof.commitment.T3
      )

      left == right
    }

    condition1 && condition2 && condition3
  }

  // Composes Dlog ciphertext's parts (fragments of c1 or c2) into a full ciphertext part (c1 or c2)
  private def compose(cts: Seq[(Seq[GroupElement], Int)])
                     (implicit dlogGroup: DiscreteLogGroup): Seq[(GroupElement, Int)] = {
    cts.map{ ct_point =>
      val (ct, point) = ct_point
      val Hm = ct.zipWithIndex.foldLeft(identity){ (product, c_i) =>
        val (c, i) = c_i
        mul(product, exp(c, base.pow(i)))
      }
      (Hm, point)
    }
  }

  // Homomorphically reconstructs (by Lagrange interpolation) encryption of a value which shares are encrypted in Dlog ciphertext's parts (c1 or c2)
  // Input:  set of encrypted shares with their evaluation points
  // Output: encryption of a reconstructed value
  private def reconstruct(cts: Seq[(GroupElement, Int)])
                         (implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    val all_points = cts.map(_._2)
    cts.foldLeft(identity){ (product, hm_point) =>
      val (hm, point) = hm_point
      val L = LagrangeInterpolation.getLagrangeCoeff(dlogGroup, point, all_points)
      mul(product, exp(hm, L))
    }
  }

  private def getC1(ct: DLogCiphertext): Seq[GroupElement] = {
    ct.C.map(_.c1)
  }
  private def getC2(ct: DLogCiphertext): Seq[GroupElement] = {
    ct.C.map(_.c2)
  }

  private def getW1(cts: Seq[(DLogCiphertext, Int)])
                   (implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    reconstruct(compose(cts.map(ct => (getC1(ct._1), ct._2))))
  }
  private def getW2(cts: Seq[(DLogCiphertext, Int)])
                   (implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    reconstruct(compose(cts.map(ct => (getC2(ct._1), ct._2))))
  }
}

object CorrectSharing {
  case class CommitmentParams(a: BigInt, b: BigInt, c: BigInt)
  case class Commitment(T1: GroupElement, T2: GroupElement, T3: GroupElement)
  case class Challenge(e: BigInt)
  case class Response(y1: BigInt, y2: BigInt, y3: BigInt)

  case class Witness(share: BigInt, shareAux: BigInt, initialRandomness: BigInt)
  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)

  case class Statement(ct: Seq[(DLogCiphertext, Int)],
                       D:  GroupElement,
                       threshold: Int){
    require(ct.size >= threshold, "Insufficient number of encrypted shares")
  }
}
