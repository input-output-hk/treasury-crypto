package io.iohk.protocol.keygen_2_0.NIZKs.rnce

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.CorrectSharesDecryption.{CRS, Challenge, Commitment, CommitmentDecryption, CommitmentDelta, CommitmentPK, CommitmentParams, CommitmentParamsDecryption, CommitmentParamsDelta, CommitmentParamsSK, CommitmentSK, Proof, Response, ResponseDecryption, ResponseDelta, ResponseSK, Statement, Witness, decryptionCommitment}
import io.iohk.protocol.keygen_2_0.encoding.BaseCodec
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCrsLight, RnceSecretKeyLight}
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.{RnceBatchedCiphertext, RnceBatchedPubKey, RnceBatchedSecretKey}
import io.iohk.protocol.keygen_2_0.utils.DlogGroupArithmetics.{div, exp, mul}

import scala.collection.mutable.ArrayBuffer

// Implementation of `Figure 17: RNCE DKG Maintaining ZK argument` in doc/rnce-based/DecisionMakingMain.pdf
case class CorrectSharesDecryption(crs: CRS, statement: Statement, implicit val group: DiscreteLogGroup) {

  private val g1 = crs.rnce_crs.g1 // mu
  private val g2 = crs.rnce_crs.g2 // rho
  private val g3 = crs.g3          // eta
  private val h  = crs.h

  private val cts = statement.cts
  private val cts1 = statement.cts1
  private val lambda = statement.lambda
  private val gammas = // gamma-coefficients appear starting from 2-nd round of Maintenance phase; So in the first round just 1-multipliers are used
    if(statement.gammas.nonEmpty){
      statement.gammas
    } else {
      Array.fill(statement.cts.length)(BigInt(1)).toSeq // values for the 1-st Maintenance round
    }

  private val l = cts.head.C.length // number of segments in batched encryption
  private val modulus = group.groupOrder

  private def randZq = group.createRandomNumber
  private def genDs = (0 until l).map(_ => group.createRandomNumber)
  private def randSKPK = RnceBatchedEncryption.keygen(RnceParams(crs.rnce_crs))

  //---------------------------------------------------------------------------
  // Delta-related part of proof
  //---------------------------------------------------------------------------
  def getCommitmentParamsDelta: CommitmentParamsDelta = {
    CommitmentParamsDelta(randZq, randZq, randZq, randZq)
  }

  def getCommitmentDelta(params: CommitmentParamsDelta, witness: Witness): CommitmentDelta = {
    val T = mul(exp(g1, params.w1), mul(exp(g2, params.w3), exp(g3, params.w4)))
    // commitment D0 = mu^s * rho^s_ * eta^o_0 - commitment of constant coefficients a0 of three Lagrange polynomials
    val Delta0 = mul(mul(exp(g1, witness.s), exp(g2, witness.s_)), exp(g3, params.o_0))

    CommitmentDelta(T, Delta0)
  }

  def getResponseDelta(params: CommitmentParamsDelta, witness: Witness, challenge: Challenge): ResponseDelta = {
    ResponseDelta(
      z7  = (params.w1 + challenge.e * witness.s)  mod modulus,
      z71 = (params.w3 + challenge.e * witness.s_) mod modulus,
      z8  = (params.w4 + challenge.e * params.o_0) mod modulus
    )
  }

  def verifyDelta(proof: Proof): Boolean = {
    val left = mul(
      proof.commitment.commDelta.T,
      exp(proof.commitment.commDelta.Delta0, proof.challenge.e)
    )
    val right = mul(
      exp(g1, proof.response.respDelta.z7),
      mul(exp(g2, proof.response.respDelta.z71), exp(g3, proof.response.respDelta.z8)))
    left == right
  }
  //---------------------------------------------------------------------------
  // Decryption-related part of proof
  //---------------------------------------------------------------------------
  def getCommitmentParamsDecryption: CommitmentParamsDecryption = {
    CommitmentParamsDecryption(
      w2 =  randZq,
      w5 =  randZq,
      ds =  cts.map(_ => genDs),
      ds1 = cts.map(_ => genDs))
  }

  def getCommitmentDecryption(params: CommitmentParamsDecryption,  paramsDelta: CommitmentParamsDelta, witness: Witness): CommitmentDecryption = {
    require(cts.length == params.ds.length)
    require(cts1.length == params.ds1.length)
    CommitmentDecryption(
      S  = mul(exp(g1, paramsDelta.w1), exp(h, params.w2)),
      S1 = mul(exp(g1, paramsDelta.w3), exp(h, params.w5)),
      D  = cts.zip(params.ds).map  {case (ct, d) => decryptionCommitment(ct, witness.sk, crs.h, d)},
      D1 = cts1.zip(params.ds1).map{case (ct, d) => decryptionCommitment(ct, witness.sk, crs.h, d)}
    )
  }

  def getResponseDecryption(params: CommitmentParamsDecryption, challenge: Challenge): ResponseDecryption = {

    def sumDs(ds: Seq[BigInt]) = ds.zipWithIndex.foldLeft(BigInt(0)){
      case (sum, (d, k) ) =>
        (sum + d * BaseCodec.defaultBase.pow(k)).mod(modulus)
    }
    val sum  = params.ds.zip(gammas).foldLeft(BigInt(0)) {case (acc, (ds_i, gamma)) => (acc + sumDs(ds_i) * gamma).mod(modulus)}
    val sum1 = params.ds1.zip(gammas).foldLeft(BigInt(0)){case (acc, (ds_i, gamma)) => (acc + sumDs(ds_i) * gamma).mod(modulus)}

    ResponseDecryption(
      (params.w2 + challenge.e * sum).mod(modulus),
      (params.w5 + challenge.e * sum1).mod(modulus),
    )
  }

  def verifyDecryption(proof: Proof): Boolean = {
    def getR(D: Seq[GroupElement]): GroupElement = {
      D.zip(gammas).foldLeft(group.groupIdentity){case(acc, (di, gamma)) => mul(acc, exp(di, gamma))}
    }

    val R  = getR(proof.commitment.commDecryption.D)
    val R1 = getR(proof.commitment.commDecryption.D1)

    def verify(R: GroupElement, S: GroupElement, z7: BigInt, z9: BigInt): Boolean = {
      val left = mul(
        S,
        exp(R, proof.challenge.e)
      )
      val right = mul(
        exp(g1, z7),
        exp(h, z9)
      )
      left == right
    }

    verify(R, proof.commitment.commDecryption.S, proof.response.respDelta.z7, proof.response.respDecryption.z9) &&
      verify(R1, proof.commitment.commDecryption.S1, proof.response.respDelta.z71, proof.response.respDecryption.z91)
  }
  //---------------------------------------------------------------------------
  // SK-related part of proof
  //---------------------------------------------------------------------------
  def getCommitmentParamsSK: CommitmentParamsSK = {
    CommitmentParamsSK(
      randSkPk  = randSKPK,
      randSkPk1 = randSKPK,
      ds =  cts.map(_ => genDs),
      ds1 = cts.map(_ => genDs))
  }

  def getCommitmentSK(params: CommitmentParamsSK): CommitmentSK = {
    require(cts.length == params.ds.length)
    require(cts1.length == params.ds1.length)
    CommitmentSK(
      D  = cts.zip(params.ds).map  {case (ct, d) => decryptionCommitment(ct, params.randSkPk._1, crs.h, d)},
      D1 = cts1.zip(params.ds1).map{case (ct, d) => decryptionCommitment(ct, params.randSkPk1._1, crs.h, d)}
    )
  }

  def getResponseSK(params: CommitmentParamsSK, paramsDecryption: CommitmentParamsDecryption, witness: Witness, challenge: Challenge): ResponseSK = {

    def getZ6(rs: Seq[BigInt], ds: Seq[BigInt]): BigInt = {
      require(rs.length == ds.length)
      rs.zip(ds).zipWithIndex.foldLeft(BigInt(0)){
        case (sum, ((r, d), k))=>
          val res = (r + challenge.e * d) * BaseCodec.defaultBase.pow(k)
          (sum + res).mod(modulus)
      }
    }

    def getZ4Z5(randSk: RnceBatchedSecretKey): Seq[(BigInt, BigInt)] = {
      require(randSk.secretKeys.length == witness.sk.secretKeys.length)
      randSk.secretKeys.zip(witness.sk.secretKeys).map{
        case (r, s) =>
          ((r.x1 + challenge.e * s.x1).mod(modulus),
           (r.x2 + challenge.e * s.x2).mod(modulus))
      }
    }

    val z4z5  = getZ4Z5(params.randSkPk._1)
    val z4z5_ = getZ4Z5(params.randSkPk1._1)

    require(params.ds.length == paramsDecryption.ds.length)
    require(params.ds1.length == paramsDecryption.ds1.length)

    ResponseSK(
      z4z5.map(_._1),
      z4z5.map(_._2),
      (params.ds, paramsDecryption.ds).zipped.map(getZ6),
      z4z5_.map(_._1),
      z4z5_.map(_._2),
      (params.ds1, paramsDecryption.ds1).zipped.map(getZ6)
    )
  }

  def verifySK(proof: Proof): Boolean = {

    def combine(ct: RnceBatchedCiphertext,
                z4z5: RnceBatchedSecretKey,
                z6: BigInt,
                e: BigInt): GroupElement = {

      require(ct.C.length == z4z5.secretKeys.length)

      val res = ct.C.zip(z4z5.secretKeys).zipWithIndex.foldLeft(group.groupIdentity){
        case (acc, ((c, z), k)) =>
          val res = div(
            exp(c.e, e + BigInt(1)),
            mul(exp(c.u1, z.x1), exp(c.u2, z.x2)), // z.x1 = z4 and z.x2 = z5
          )
          mul(acc, exp(res, BaseCodec.defaultBase.pow(k)))
      }
      mul(res, exp(h, z6))
    }

    def verify(P: GroupElement, D: GroupElement, ct: RnceBatchedCiphertext, z4z5: RnceBatchedSecretKey, z6: BigInt): Boolean = {
      val left = mul(
        P,
        exp(D, proof.challenge.e)
      )
      val right = combine(ct, z4z5, z6, proof.challenge.e)
      left == right
    }

    val res = ArrayBuffer[Boolean]()

    val z4z5Sk = RnceBatchedSecretKey((proof.response.respSK.z4, proof.response.respSK.z5).zipped.map(RnceSecretKeyLight))

    for (i <- proof.commitment.commSK.D.indices){
      res += verify(
        proof.commitment.commSK.D(i),
        proof.commitment.commDecryption.D(i),
        cts(i),
        z4z5Sk,
        proof.response.respSK.z6(i)
      )
    }

    val z4z5Sk1 = RnceBatchedSecretKey((proof.response.respSK.z41, proof.response.respSK.z51).zipped.map(RnceSecretKeyLight))

    for (i <- proof.commitment.commSK.D1.indices){
      res += verify(
          proof.commitment.commSK.D1(i),
          proof.commitment.commDecryption.D1(i),
          cts1(i),
          z4z5Sk1,
          proof.response.respSK.z61(i)
        )
    }

    res.forall(_ == true)
  }

  //---------------------------------------------------------------------------
  // PK-related part of proof
  //---------------------------------------------------------------------------

  def combineBatchedPK(pk: RnceBatchedPubKey): GroupElement = {
    pk.pubKeys.zipWithIndex.foldLeft(group.groupIdentity){
      case (acc, (pk_i, i)) =>
        mul(acc, exp(pk_i.h, lambda.pow(i)))
    }
  }

  def getCommitmentPK(params: CommitmentParamsSK): CommitmentPK = {
    require(cts.length == params.ds.length)
    require(cts1.length == params.ds1.length)
    CommitmentPK(
      Q  = combineBatchedPK(params.randSkPk._2),
      Q1 = combineBatchedPK(params.randSkPk1._2)
    )
  }

  def verifyPK(proof: Proof, pubKey: RnceBatchedPubKey): Boolean = {
    def verify(Q: GroupElement, pk: RnceBatchedPubKey, z4: BigInt, z5: BigInt): Boolean = {
      val left = mul(Q, exp(combineBatchedPK(pk), proof.challenge.e))
      val right = mul(
        exp(g1, z4),
        exp(g2, z5)
      )
      left == right
    }

    def combineZ(z: Seq[BigInt]): BigInt = {
      z.zipWithIndex.foldLeft(BigInt(0)){
        case (sum, (z_i, i)) =>
          (sum + z_i * lambda.pow(i)).mod(modulus)
      }
    }

    verify(proof.commitment.commPK.Q, pubKey, combineZ(proof.response.respSK.z4), combineZ(proof.response.respSK.z5)) &&
      verify(proof.commitment.commPK.Q1, pubKey, combineZ(proof.response.respSK.z41), combineZ(proof.response.respSK.z51))
  }

  //---------------------------------------------------------------------------
  // Common proof section
  //---------------------------------------------------------------------------
  def getCommitmentParams: CommitmentParams = {
    CommitmentParams(
      getCommitmentParamsDelta,
      getCommitmentParamsDecryption,
      getCommitmentParamsSK
    )
  }

  def getCommitment(params: CommitmentParams, witness: Witness): Commitment = {
    Commitment(
      getCommitmentDelta(params.paramsDelta, witness),
      getCommitmentDecryption(params.paramsDecryption, params.paramsDelta, witness),
      getCommitmentSK(params.paramsSK),
      getCommitmentPK(params.paramsSK)
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, challenge: Challenge): Response = {
    Response(
      getResponseDelta(params.paramsDelta, witness, challenge),
      getResponseDecryption(params.paramsDecryption, challenge),
      getResponseSK(params.paramsSK, params.paramsDecryption, witness, challenge)
    )
  }

  def getChallenge: Challenge = {
    Challenge(e = randZq)
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

  def verify(proof: Proof, pubKey: RnceBatchedPubKey): Boolean = {
    verifyDelta(proof) &&
      verifyDecryption(proof) &&
      verifySK(proof) &&
      verifyPK(proof, pubKey)
  }
  //---------------------------------------------------------------------------
}

object CorrectSharesDecryption {

  case class CRS(rnce_crs:  RnceCrsLight,  // g1 = mu, g2 = rho
                 g3:        GroupElement,  // g3 = eta
                 h:         GroupElement)

  case class CommitmentParams(paramsDelta: CommitmentParamsDelta,
                              paramsDecryption: CommitmentParamsDecryption,
                              paramsSK: CommitmentParamsSK)
  case class CommitmentParamsDelta(w1: BigInt, w3: BigInt, w4: BigInt, o_0: BigInt)
  case class CommitmentParamsDecryption(w2: BigInt, w5: BigInt,
                                        ds: Seq[Seq[BigInt]],  ds1: Seq[Seq[BigInt]])
  case class CommitmentParamsSK(randSkPk: (RnceBatchedSecretKey, RnceBatchedPubKey), randSkPk1: (RnceBatchedSecretKey, RnceBatchedPubKey),
                                ds: Seq[Seq[BigInt]], ds1: Seq[Seq[BigInt]])

  case class Commitment(commDelta: CommitmentDelta,
                        commDecryption: CommitmentDecryption,
                        commSK: CommitmentSK,
                        commPK: CommitmentPK){
    val size: Int = {
      commDelta.size + commDecryption.size + commSK.size + commPK.size
    }
  }
  case class CommitmentDelta(T: GroupElement, Delta0: GroupElement){
    val size: Int = {
      T.bytes.length + Delta0.bytes.length
    }
  }
  case class CommitmentDecryption(S: GroupElement, S1: GroupElement,
                                  D: Seq[GroupElement], D1: Seq[GroupElement]){
    val size: Int = {
      S.bytes.length + S1.bytes.length +
        D.foldLeft(0)((sum, d) => sum + d.bytes.length) +
        D1.foldLeft(0)((sum, d) => sum + d.bytes.length)
    }
  }
  case class CommitmentSK(D: Seq[GroupElement], D1: Seq[GroupElement]){
    val size: Int = {
      D.foldLeft(0)((sum, d) => sum + d.bytes.length) +
        D1.foldLeft(0)((sum, d) => sum + d.bytes.length)
    }
  }
  case class CommitmentPK(Q: GroupElement, Q1: GroupElement){
    val size: Int = {
      Q.bytes.length + Q1.bytes.length
    }
  }

  case class Response(respDelta: ResponseDelta,
                      respDecryption: ResponseDecryption,
                      respSK: ResponseSK){
    val size: Int = {
      respDelta.size + respDecryption.size + respSK.size
    }
  }
  case class ResponseDelta(z7: BigInt, z71: BigInt, z8: BigInt){
    val size: Int = {
      z7.toByteArray.length + z71.toByteArray.length + z8.toByteArray.length
    }
  }
  case class ResponseDecryption(z9: BigInt, z91: BigInt){
    val size: Int = {
      z9.toByteArray.length + z91.toByteArray.length
    }
  }
  case class ResponseSK(z4:  Seq[BigInt], z5:  Seq[BigInt], z6: Seq[BigInt],
                        z41: Seq[BigInt], z51: Seq[BigInt], z61: Seq[BigInt]){
    val size: Int = {
      z4.foldLeft(0)((sum, z) => sum + z.toByteArray.length) +
        z5.foldLeft(0)((sum, z) => sum + z.toByteArray.length) +
        z6.foldLeft(0)((sum, z) => sum + z.toByteArray.length) +
        z41.foldLeft(0)((sum, z) => sum + z.toByteArray.length) +
        z51.foldLeft(0)((sum, z) => sum + z.toByteArray.length) +
        z61.foldLeft(0)((sum, z) => sum + z.toByteArray.length)
    }
  }

  case class Challenge(e: BigInt)

  // secrets which are intended to be shared
  case class Witness(s: BigInt,   // secret value s
                     s_ : BigInt,
                     sk: RnceBatchedSecretKey) // secret value s_

  case class Proof(commitment: Commitment, challenge: Challenge, response: Response){
    val size: Int = {
      commitment.size + response.size
    }
  }

  case class Statement(cts: Seq[RnceBatchedCiphertext],
                       cts1: Seq[RnceBatchedCiphertext],
                       lambda: BigInt,
                       gammas: Seq[BigInt] = Seq())

  def decryptionCommitment(ct: RnceBatchedCiphertext,
                           sk: RnceBatchedSecretKey,
                           h: GroupElement,
                           ds: Seq[BigInt])
                          (implicit group: DiscreteLogGroup): GroupElement = {

    require(ct.C.length == sk.secretKeys.length)
    require(ds.length   == sk.secretKeys.length)

    ct.C.zip(sk.secretKeys).zip(ds).zipWithIndex.foldLeft(group.groupIdentity){
      case (acc, (((c, sk), d), k)) =>
        val decryption = div(c.e, mul(exp(c.u1, sk.x1), exp(c.u2, sk.x2)))
        val res = exp(
          mul(decryption, exp(h, d)),
          BaseCodec.defaultBase.pow(k)
        )
        mul(acc, res)
    }
  }
}
