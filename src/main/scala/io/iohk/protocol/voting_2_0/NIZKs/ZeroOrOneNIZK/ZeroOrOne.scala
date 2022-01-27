package io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{combine, exp, mul}
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.ZeroOrOne.{CommitmentParams, Statement, Witness}
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.datastructures.{Proof, Commitment, Response}

case class ZeroOrOne(statement: Statement)
                    (implicit dlogGroup: DiscreteLogGroup){
  private val g = dlogGroup.groupGenerator
  private val n = statement.vec.size
  private val modulus = dlogGroup.groupOrder

  private val vec = statement.vec
  private val pk = statement.pubKey

  private val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val lambda = getLambda(statement)

  def getLambda(statement: Statement): BigInt = {
    BigInt(1,
      sha.hash(statement.vec.foldLeft(Array[Byte]())((buffer, c) => buffer ++ c.bytes))
    ).mod(n)
  }

  def getChallenge(commitment: Commitment): BigInt = {
    BigInt(1,
      sha.hash(
        commitment.A.bytes ++
        commitment.B.bytes ++
        commitment.E.bytes ++
        commitment.F.bytes
      )
    ).mod(n)
  }

  def getCommitmentParams: CommitmentParams = {
    CommitmentParams(
      r = vec.indices.map(_ => dlogGroup.createRandomNumber),
      m = vec.indices.map(_ => dlogGroup.createRandomNumber),
      q = vec.indices.map(_ => dlogGroup.createRandomNumber)
    )
  }

  def getCommitment(params: CommitmentParams, witness: Witness)
                   (implicit dlogGroup: DiscreteLogGroup): Commitment = {
    assert(params.r.size == params.m.size && params.m.size == params.q.size)

    val C1 = params.r.map(exp(g, _))
    val C2 = params.r.zip(params.m).map{
      case(r_i, m_i) => mul(exp(g, m_i), exp(pk, r_i))
    }
    val a = params.q.map(exp(g, _))
    val b = params.q.zip(params.m).zip(witness.m).map{
      case((q_i, m_i_), m_i) => mul(exp(g, (m_i * m_i_).mod(modulus)), exp(pk, q_i))
    }

    Commitment(
      A = combine(a, lambda),
      B = combine(b, lambda),
      E = combine(C1, lambda),
      F = combine(C2, lambda)
    )
  }

  def getResponse(params: CommitmentParams, witness: Witness, e: BigInt): Response = {
    val z1 = params.r.zip(witness.r).map{
      case(r_i_, r_i) => (r_i_ + r_i * e).mod(modulus)
    }
    val z2 = params.m.zip(witness.m).map{
      case(m_i_, m_i) => (m_i_ + m_i * e).mod(modulus)
    }
    val z3 = params.q.zip(witness.r).zip(z2).map{
      case((q_i, r_i), z2_i) => (q_i + r_i * (e - z2_i).mod(modulus)).mod(modulus)
    }
    Response(
      Z1 = combine(z1, lambda),
      z2,
      Z3 = combine(z3, lambda)
    )
  }

  def prove(witness: Witness)
           (implicit dlogGroup: DiscreteLogGroup): Proof = {

    val params = getCommitmentParams
    val commitment = getCommitment(params, witness)

    Proof(
      commitment,
      getResponse(params, witness, getChallenge(commitment))
    )
  }

  def combineWithZ2(c: Seq[GroupElement], z2: Seq[BigInt], e: BigInt): GroupElement = {
    c.zip(z2).zipWithIndex.foldLeft(dlogGroup.groupIdentity){
      case(product, ((c_i, z2_i), i)) =>
        mul(product, exp(c_i, (lambda.modPow(BigInt(i), modulus) * (e - z2_i).mod(modulus)).mod(modulus)))
    }
  }

  def verify(proof: Proof)
            (implicit dlogGroup: DiscreteLogGroup): Boolean = {
    val e = getChallenge(proof.commitment)

    val c1 = vec.map(_.c1)
    val c2 = vec.map(_.c2)

    val C = combine(c1, lambda)
    val D = combine(c2, lambda)
    val Z2 = combine(proof.response.z2, lambda)

    def condition1: Boolean = {
      mul(exp(C, e), proof.commitment.E) == exp(g, proof.response.Z1)
    }

    def condition2: Boolean = {
      mul(exp(D, e), proof.commitment.F) == mul(exp(g, Z2), exp(pk, proof.response.Z1))
    }

    def condition3: Boolean = {
      mul(combineWithZ2(c1, proof.response.z2, e), proof.commitment.A) == exp(g, proof.response.Z3)
    }

    def condition4: Boolean = {
      mul(combineWithZ2(c2, proof.response.z2, e), proof.commitment.B) == exp(pk, proof.response.Z3)
    }

    condition1 && condition2 && condition3 && condition4
  }
}

object ZeroOrOne {
  case class CommitmentParams(r: Seq[BigInt], m: Seq[BigInt], q: Seq[BigInt])

  case class Statement(pubKey: PubKey, vec: Seq[ElGamalCiphertext])
  case class Witness(m: Seq[BigInt], r: Seq[BigInt])
}
