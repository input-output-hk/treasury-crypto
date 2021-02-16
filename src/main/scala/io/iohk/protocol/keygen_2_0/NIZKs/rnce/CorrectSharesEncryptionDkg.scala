package io.iohk.protocol.keygen_2_0.NIZKs.rnce

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.CorrectSharesEncryptionDkg._
import io.iohk.protocol.keygen_2_0.encoding.BaseCodec
import io.iohk.protocol.keygen_2_0.math.Polynomial
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.{RnceBatchedCiphertext, RnceBatchedPubKey, RnceBatchedRandomness}
import io.iohk.protocol.keygen_2_0.utils.DlogGroupArithmetics.{exp, mul}


// DKG-phase NIZK-proof for correctness of encrypted shares together with correctness of their encryptions
case class CorrectSharesEncryptionDkg(crs:   CRS,
                                      statement: Statement,
                                      implicit val group: DiscreteLogGroup) {

  private val g1 = crs.rnce_crs.g1 // mu
  private val g2 = crs.rnce_crs.g2 // rho
  private val g3 = crs.g3          // eta

  private val M2 = statement.ct1_ct2.length  // number of Holding committee members
  private val l = statement.ct1_ct2.head._1.C.size // number of segments in batched ciphertexts

  require(statement.ct1_ct2.forall(_._1.C.size == l))
  require(statement.ct1_ct2.forall(_._2.C.size == l))

  private val modulus = group.groupOrder

  private def randZq = group.createRandomNumber
  private def getBatchedRandomness(l: Int) = RnceBatchedRandomness(for(_ <- 0 until l) yield { randZq })

  def getLambda(deltas: Seq[GroupElement]): BigInt = {
    val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
    BigInt(1,
      sha.hash(deltas.foldLeft(Array[Byte]())((buffer, D) => buffer ++ D.bytes))
    ).mod(modulus)
  }

  def commitCoeffs(F1_coeffs: Seq[BigInt], F2_coeffs: Seq[BigInt], o: Seq[BigInt]): Seq[GroupElement] = {
    require(F1_coeffs.length == F2_coeffs.length)
    require(F2_coeffs.length == o.length)

    for(i <- F1_coeffs.indices) yield {
      product(Seq(exp(g1, F1_coeffs(i)), exp(g2, F2_coeffs(i)), exp(g3, o(i))))
    }
  }

  def combineCoeffs(coeffs: Seq[BigInt], lambda: BigInt, n: Int): BigInt = {
    val poly = Polynomial(group, coeffs.length - 1, coeffs.head, coeffs.tail)
    (1 to n).map{ i =>
      (poly.evaluate(i) * (lambda.pow(i - 1) mod modulus)) mod modulus
    }.foldLeft(BigInt(0)){ (sum, v) => (sum + v) mod modulus }
  }

  def sumBatchedRandomness(r:      Seq[RnceBatchedRandomness],
                           lambda: BigInt): BigInt = {
    r.zipWithIndex.foldLeft(BigInt(0)){
      (sum, r_batched_j) =>
        val (r_batched, j) = r_batched_j
        (sum + (r_batched.R.foldLeft(BigInt(0)){
          (sum_batched, r_i) => (sum_batched + r_i) mod modulus
        } * lambda.pow(j) mod modulus)) mod modulus
    }
  }

  private def product(elems: Seq[GroupElement]): GroupElement = {
    elems.foldLeft(group.groupIdentity){
      (result, e_i) => mul(result, e_i)
    }
  }

  private def combinePublicKeys(pubKeysBatched:   Seq[RnceBatchedPubKey],
                                exponentsBatched: Seq[RnceBatchedRandomness],
                                lambda:           BigInt): GroupElement = {
    require(pubKeysBatched.length == exponentsBatched.length)

    product(
      pubKeysBatched.zip(exponentsBatched).zipWithIndex.map{
        batch =>
          val (pubKeys, exponents, j) = (batch._1._1.pubKeys.map(_.h), batch._1._2.R, batch._2)
          require(pubKeys.length == exponents.length)

          exp(
            product(
              pubKeys.zip(exponents)
                .map(pk_e => exp(pk_e._1, pk_e._2))
            ), lambda.pow(j) mod modulus
          )
      }
    )
  }

  private def combineDeltas(deltas: Seq[GroupElement],
                            lambda: BigInt, n: Int): GroupElement = {
    product(
      (1 to n).map{
        j =>
          exp(
            product(
              deltas.zipWithIndex.map{
                delta_t =>
                  val (delta, t) = delta_t
                  exp(delta, BigInt(j).pow(t) mod modulus)
              }
            ), lambda.pow(j - 1) mod modulus
          )
      }
    )
  }

  private def combineCiphertexts(ctsBatched: Seq[Seq[GroupElement]],
                                 lambda: BigInt, p: BigInt): GroupElement = {
    product(
      ctsBatched.zipWithIndex.map{
        cts_j =>
          val (cts, j) = cts_j
          exp(
            product(
              cts.zipWithIndex.map{
                ct_t =>
                  val (ct, t) = ct_t
                  exp(ct, p.pow(t) mod modulus)
              }
            ), lambda.pow(j) mod modulus
          )
      }
    )
  }

  def responseForRandomness(f_batched: Seq[RnceBatchedRandomness],
                            r_batched: Seq[RnceBatchedRandomness],
                            e: BigInt, p: BigInt): Seq[RnceBatchedRandomness] = {
    f_batched.zip(r_batched).map{
      batch =>
        val (f_j, r_j) = (batch._1.R, batch._2.R)
        require(f_j.length == r_j.length)

        RnceBatchedRandomness(
          f_j.zip(r_j).zipWithIndex.map{
            f_r_k =>
              val ((f, r), k) = f_r_k
              (f + r * p.pow(k) * e) mod modulus
          }
        )
    }
  }

  // Parameters for a proof based on a (t2, M2)-threshold scheme, where:
  //  t2 - sharing threshold, degree of Lagrange polynomials;
  //  M2 - number of committee members in the next committee, for which a secret (a{0}, a'{0}) is shared;
  //  l  - number of segments into which each encrypted share is separated to make feasible Dlog search during decryption
  def getCommitmentParams(t2: Int, M2: Int, l: Int): CommitmentParams = {
    CommitmentParams(
      t2, M2, l,
      o = for(_ <- 0 until t2) yield { randZq },
      b = randZq,
      c = randZq,
      d = randZq,
      f1_f2 = for(_ <- 0 until M2) yield { (getBatchedRandomness(l), getBatchedRandomness(l)) }
    )
  }

  def getCommitment(params: CommitmentParams, witness: Witness, statement: Statement): (Commitment, BigInt) = {
    val f1_seq = params.f1_f2.map(_._1)
    val f2_seq = params.f1_f2.map(_._2)

    val deltas = commitCoeffs(witness.F1_coeffs, witness.F2_coeffs, params.o)
    val lambda = getLambda(deltas)

    val f1_sum = sumBatchedRandomness(f1_seq, lambda)
    val f2_sum = sumBatchedRandomness(f2_seq, lambda)

    val commitment =
      Commitment(
        CommitmentBatch(
          A = exp(g1, f1_sum),
          B = exp(g2, f1_sum),
          C = mul(exp(g1, params.b), combinePublicKeys(statement.pubKeys, f1_seq, lambda))
        ),
        CommitmentBatch(
          A = exp(g1, f2_sum),
          B = exp(g2, f2_sum),
          C = mul(exp(g1, params.c), combinePublicKeys(statement.pubKeys, f2_seq, lambda))
        ),
        T = product(Seq(exp(g1, params.b), exp(g2, params.c), exp(g3, params.d))),
        deltas
      )
    (commitment, lambda)
  }

  def getChallenge: Challenge = {
    Challenge(e = randZq)
  }


  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge, lambda: BigInt): Response = {
    val e = challenge.e
    val n = group.groupOrder
    val p = BaseCodec.defaultBase

    val f1_seq = params.f1_f2.map(_._1)
    val f2_seq = params.f1_f2.map(_._2)
    val r1_seq = witness.r1_r2.map(_._1)
    val r2_seq = witness.r1_r2.map(_._2)

    Response(
      z1 = (params.b + combineCoeffs(witness.F1_coeffs, lambda, M2) * e) mod n,
      z2 = (params.c + combineCoeffs(witness.F2_coeffs, lambda, M2) * e) mod n,
      z3 = (params.d + combineCoeffs(params.o, lambda, M2) * e) mod n,
      z41_z42 = responseForRandomness(f1_seq, r1_seq, e, p).zip(responseForRandomness(f2_seq, r2_seq, e, p))
    )
  }

  def prove(witness: Witness): Proof = {
    require(witness.F1_coeffs.size == witness.F2_coeffs.size)
    require(witness.r1_r2.forall(_._1.R.size == l))
    require(witness.r1_r2.forall(_._2.R.size == l))

    // Threshold parameters (t, n) = (t2, M2)
    val t2 = witness.F1_coeffs.size   // threshold
    require(witness.r1_r2.size == M2) // number of Holding committee members

    val params = getCommitmentParams(t2, M2, l)
    val challenge = getChallenge
    val (commitment, lambda) = getCommitment(params, witness, statement)

    Proof(
      commitment,
      challenge,
      getResponse(params, witness, challenge, lambda)
    )
  }

  def verifySharesCorrectness(proof: Proof, lambda: BigInt): Boolean = {
    val delta = combineDeltas(proof.commitment.deltas, lambda, M2)

    val left = product(Seq(exp(g1, proof.response.z1), exp(g2, proof.response.z2), exp(g3, proof.response.z3)))
    val right = mul(exp(delta, proof.challenge.e), proof.commitment.T)

    left == right
  }

  def verifyBatch(batch:      CommitmentBatch,
                  cts:        Seq[RnceBatchedCiphertext],
                  z4_seq:     Seq[RnceBatchedRandomness],
                  z4_sum:     BigInt,
                  z:          BigInt,
                  challenge:  Challenge,
                  lambda:     BigInt): Boolean = {
    val condition1 =
      mul(
        exp(combineCiphertexts(cts.map(_.C.map(_.u1)), lambda, BaseCodec.defaultBase), challenge.e),
        batch.A
      ) == exp(g1, z4_sum)

    val condition2 =
      mul(
        exp(combineCiphertexts(cts.map(_.C.map(_.u2)), lambda, BaseCodec.defaultBase), challenge.e),
        batch.B
      ) == exp(g2, z4_sum)

    val condition3 =
      mul(
        exp(combineCiphertexts(cts.map(_.C.map(_.e)), lambda, BaseCodec.defaultBase), challenge.e),
        batch.C
      ) == mul(exp(g1, z), combinePublicKeys(statement.pubKeys, z4_seq, lambda))

    condition1 && condition2 && condition3
  }

  def verifyEncryptionCorrectness(proof: Proof, lambda: BigInt): Boolean = {
    val z41_seq = proof.response.z41_z42.map(_._1)
    val z42_seq = proof.response.z41_z42.map(_._2)

    val z41_sum = sumBatchedRandomness(z41_seq, lambda)
    val z42_sum = sumBatchedRandomness(z42_seq, lambda)

    val ct1_seq = statement.ct1_ct2.map(_._1)
    val ct2_seq = statement.ct1_ct2.map(_._2)

    verifyBatch(proof.commitment.batch1, ct1_seq, z41_seq, z41_sum, proof.response.z1, proof.challenge, lambda) &&
    verifyBatch(proof.commitment.batch2, ct2_seq, z42_seq, z42_sum, proof.response.z2, proof.challenge, lambda)
  }

  def verify(proof: Proof): Boolean = {
    val lambda = getLambda(proof.commitment.deltas)
    verifySharesCorrectness(proof, lambda) && verifyEncryptionCorrectness(proof, lambda)
  }
}

object CorrectSharesEncryptionDkg {

  case class CRS(rnce_crs:  RnceCrsLight,  // g1 = mu, g2 = rho
                 g3:        GroupElement)  // g3 = eta

  case class CommitmentParams(t2: Int, M2: Int, l: Int,
                              o: Seq[BigInt], b: BigInt, c: BigInt, d: BigInt, f1_f2: Seq[(RnceBatchedRandomness, RnceBatchedRandomness)])

  case class CommitmentBatch(A: GroupElement, B: GroupElement, C: GroupElement)
  case class Commitment(batch1: CommitmentBatch, batch2: CommitmentBatch, T: GroupElement, deltas: Seq[GroupElement])

  case class Challenge(e: BigInt)

  case class Response(z1: BigInt, z2: BigInt, z3: BigInt,
                      z41_z42: Seq[(RnceBatchedRandomness, RnceBatchedRandomness)])

  case class Proof(commitment: Commitment, challenge: Challenge, response: Response)

  case class Statement(ct1_ct2: Seq[(RnceBatchedCiphertext, RnceBatchedCiphertext)], // encrypted shares s_j and s'_j for j = [0, M2)
                       pubKeys: Seq[RnceBatchedPubKey]) // public keys used for encryption of an each pair of (s, s')

  case class Witness(r1_r2: Seq[(RnceBatchedRandomness, RnceBatchedRandomness)], // (r_j,  r'_j) for j = [0, M2)
                     F1_coeffs: Seq[BigInt],  // coefficients (a{0}... a{t2-1}) of polynomial F
                     F2_coeffs: Seq[BigInt])  // coefficients (a'{0}... a'{t2-1}) of polynomial F'
}
