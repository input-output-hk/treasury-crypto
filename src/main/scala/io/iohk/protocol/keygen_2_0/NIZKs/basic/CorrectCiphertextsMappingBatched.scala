package io.iohk.protocol.keygen_2_0.NIZKs.basic

import com.google.common.primitives.Longs
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.common.dlog_encryption.{DLogCiphertext, DLogRandomness}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{_}
import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectCiphertextsMappingBatched.{Challenge, Commitment, CommitmentParams, Proof, Response, Statement, Witness}
import io.iohk.protocol.keygen_2_0.NIZKs.utils.Combining.combine

case class CorrectCiphertextsMappingBatched(pubKeysFrom: Seq[PubKey],
                                            pubKeyTo:    PubKey,
                                            statement:   Statement,
                                            dlogGroup:   DiscreteLogGroup) {
  private val g = dlogGroup.groupGenerator
  private val n = dlogGroup.groupOrder

  private val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  require(pubKeysFrom.length == statement.ctsFrom.length, "Different number of public keys and ciphertexts in ctsFrom")
  require(statement.ctsFrom.length == statement.ctsTo.length, "Different number of ciphertexts in ctsFrom and ctsTo")

  // Ciphertexts order-dependent lambda
  private val all_ciphertexts_hash = sha.hash(
    statement.ctsFrom.zip(statement.ctsTo).foldLeft(Array[Byte]()){
      (buffer, ctFrom_ctTo) =>
        val (ctFrom, ctTo) = ctFrom_ctTo
        buffer ++
          ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
          ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes) ++
          ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
          ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes)
    }
  )
  private val lambdas = statement.ctsFrom.indices.map(
    i => BigInt(1, sha.hash(all_ciphertexts_hash ++ Longs.toByteArray(i))).mod(n)
  )

  //  // Ciphertexts order-independent lambda
  //  private val lambdas = statement.ctsFrom.zip(statement.ctsTo).map{
  //    ctFrom_ctTo =>
  //      val (ctFrom, ctTo) = ctFrom_ctTo
  //      BigInt(1,
  //        sha.hash(
  //          ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
  //          ctFrom.C.foldLeft(Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes) ++
  //          ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c1.bytes) ++
  //          ctTo.C.foldLeft  (Array[Byte]())((buffer, C) => buffer ++ C.c2.bytes)
  //        )
  //      ).mod(n)
  //  }

  def getCommitmentParams(): CommitmentParams = {
    CommitmentParams(
      for(_ <- pubKeysFrom.indices) yield (dlogGroup.createRandomNumber, dlogGroup.createRandomNumber) // wv
    )
  }

  def getCommitment(params: CommitmentParams)
                   (implicit dlogGroup: DiscreteLogGroup): Commitment = {
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

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge)
                 (implicit dlogGroup: DiscreteLogGroup): Response = {

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
