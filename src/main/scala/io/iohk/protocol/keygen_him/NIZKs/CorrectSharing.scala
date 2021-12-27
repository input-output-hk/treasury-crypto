package io.iohk.protocol.keygen_him.NIZKs

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.CommitteeIdentifier
import io.iohk.protocol.common.datastructures.{SecretShare, Share}
import io.iohk.protocol.common.encoding.BaseCodec
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{evaluateLiftedPoly, exp, mul}
import io.iohk.protocol.keygen_him.IdPointMap
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharing.{CommitmentParams, Statement, Witness, combine, decodeLifted}
import io.iohk.protocol.keygen_him.NIZKs.datastructures.{Commitment, Proof, Response}

case class CorrectSharing(h: GroupElement,
                          pubKeysIn: Seq[PubKey],
                          statement: Statement)
                         (implicit dlogGroup: DiscreteLogGroup){
  private val g = dlogGroup.groupGenerator
  private val n = pubKeysIn.size
  private val modulus = dlogGroup.groupOrder

  val keyToIdMap = new CommitteeIdentifier(pubKeysIn)
  private val pubKeys = pubKeysIn.sortBy(pk => IdPointMap.toPoint(keyToIdMap.getId(pk).get))

  private val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  def getLambda(statement: Statement): BigInt = {
    BigInt(1,
      sha.hash(
        statement.C.foldLeft(Array[Byte]())((buffer, c) => buffer ++ c.bytes) ++
        statement.encShares.foldLeft(Array[Byte]())((buffer, encShare) => buffer ++ encShare.bytes)
      )).mod(n)
  }

  def getChallenge(commitment: Commitment): BigInt ={
    BigInt(1,
      sha.hash(
        commitment.A.bytes ++
        commitment.B.foldLeft(Array[Byte]())((buffer, b) => buffer ++ b.bytes) ++
        commitment.C.bytes
      )
    ).mod(n)
  }

  def getCommitmentParams: CommitmentParams = {
    val lambda = getLambda(statement)
    val a = (1 to n).map(_ => dlogGroup.createRandomNumber)
    val c = (1 to n).map(_ => dlogGroup.createRandomNumber)
    CommitmentParams(
      a, c,
      a_batch = combine(a, lambda),
      c_batch = combine(c, lambda),
      b = dlogGroup.createRandomNumber
    )
  }

  def getCommitment(params: CommitmentParams)
                   (implicit dlogGroup: DiscreteLogGroup): Commitment = {
    assert(pubKeys.size == params.a.size && params.a.size == params.c.size)
    Commitment(
      A = mul(exp(g, params.a_batch), exp(h, params.b)),
      B = (0 until n).map(i => mul(exp(g, params.a(i)), exp(pubKeys(i), params.c(i)))),
      C = exp(g, params.c_batch)
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, lambda: BigInt, e: BigInt): Response = {
    // ordering s_r by evaluation points of the shares
    val s_r_sorted = witness.s_r.sortBy(_._1.point)

    val shares = s_r_sorted.map(_._1.value)
    val Z1 = shares.zip(params.a).map{ case(s, a) => (s * e + a).mod(modulus) }

    val randomness = s_r_sorted.map(_._2)
    val Z3 = randomness.zip(params.c).map{ case(r, c) => (BaseCodec.decode(r) * e + c).mod(modulus)}

    val points = s_r_sorted.map(_._1.point)
    assert(points.size == n)

    val randomnessBatched = combine(
      points.map(evalPoint =>
        Polynomial(dlogGroup, witness.randomnessCoeffs.length - 1,
          witness.randomnessCoeffs.head, witness.randomnessCoeffs.tail).evaluate(evalPoint)
      ), lambda
    )
    val Z2 = (randomnessBatched * e + params.b).mod(modulus)
    Response(Z1, Z2, Z3)
  }

  def prove(witness: Witness)
           (implicit dlogGroup: DiscreteLogGroup): Proof = {
    val params = getCommitmentParams
    val commitment = getCommitment(params)

    val lambda = getLambda(statement)
    val e = getChallenge(commitment)

    Proof(
      commitment,
      getResponse(params, witness, lambda, e)
    )
  }

  def verify(proof: Proof)
            (implicit dlogGroup: DiscreteLogGroup): Boolean = {
    val lambda = getLambda(statement)
    val e = getChallenge(proof.commitment)

    val encShares_sorted = statement.encShares.sortBy(encS => IdPointMap.toPoint(encS.receiverID))
    val points = encShares_sorted.map(encS => IdPointMap.toPoint(encS.receiverID))

    assert(points.size == n)

    val Z1_batched = combine(proof.response.Z1, lambda)
    val Z3_batched = combine(proof.response.Z3, lambda)
    val D = combine(
      points.map(evalPoint => evaluateLiftedPoly(statement.C, evalPoint)),
      lambda
    )
    val E = encShares_sorted.map(_.S.C.map(_.c2)).map(decodeLifted)
    val F = combine(
      encShares_sorted.map(_.S.C.map(_.c1)).map(decodeLifted),
      lambda
    )

    def condition1: Boolean = {
      mul(exp(D, e), proof.commitment.A) ==
        mul(exp(g, Z1_batched), exp(h, proof.response.Z2))
    }

    def condition2: Boolean = {
      E.indices.forall{
        j =>
          mul(exp(E(j), e), proof.commitment.B(j)) ==
            mul(exp(g, proof.response.Z1(j)), exp(pubKeys(j), proof.response.Z3(j)))
      }
    }

    def condition3: Boolean = {
      mul(exp(F, e), proof.commitment.C) ==
        exp(g, Z3_batched)
    }

    condition1 && condition2 && condition3
  }
}

object CorrectSharing {
  case class CommitmentParams(a: Seq[BigInt], c: Seq[BigInt],
                              a_batch: BigInt, c_batch: BigInt, b: BigInt)

  case class Witness(s_r: Seq[(Share, Seq[BigInt])], randomnessCoeffs: Seq[BigInt])
  case class Statement(C: Seq[GroupElement], encShares: Seq[SecretShare])

  def combine(scalars: Seq[BigInt], lambda: BigInt)
             (implicit dlogGroup: DiscreteLogGroup): BigInt = {
    Polynomial(dlogGroup, scalars.length - 1, scalars.head, scalars.tail).evaluate(lambda)
  }

  def combine(elements: Seq[GroupElement], lambda: BigInt)
             (implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    evaluateLiftedPoly(elements, lambda)
  }

  // Composes Dlog-encrypted lifted parts (fragments of c1 or c2) into a full lifted encrypted part (c1 or c2)
  private def decodeLifted(ctParts: Seq[GroupElement])
                          (implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    ctParts.zipWithIndex.foldLeft(dlogGroup.groupIdentity){
        case (product, (c, i))=>
          mul(product, exp(c, BaseCodec.defaultBase.modPow(BigInt(i), dlogGroup.groupOrder)))
    }
  }
}
