package io.iohk.nizk.shvzk

import io.iohk.core.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.primitives.hash.CryptographicHash
import io.iohk.core.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.encryption.PubKey
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.primitives.hash.CryptographicHash

import scala.util.Try

class SHVZKVerifier(pubKey: PubKey,
                    unitVector: Seq[ElGamalCiphertext],
                    proof: SHVZKProof)
                   (override implicit val dlog: DiscreteLogGroup,
                    override implicit val hashFunction: CryptographicHash) extends SHVZKCommon(pubKey, unitVector) {

  private val statement = unitVector.foldLeft(Array[Byte]()) {
    (acc, c) => acc ++ c.c1.bytes ++ c.c2.bytes
  }
  private val commitment = proof.IBA.foldLeft(Array[Byte]()) {
    (acc, c) => acc ++ c._1.bytes ++ c._2.bytes ++ c._3.bytes
  }

  /* Compute first verifier challange */
  private val y = {
    hashFunction.hash(pubKey.bytes ++ statement ++ commitment)
  }
  private val Y = BigInt(1, y)

  /* Compute second verifier challange */
  private val x = {
    val commitment2 = proof.Dk.foldLeft(Array[Byte]()) {
      (acc, d) => acc ++ d.c1.bytes ++ d.c2.bytes
    }
    hashFunction.hash(pubKey.bytes ++ statement ++ commitment ++ commitment2)
  }
  private val X = BigInt(1, x)


  def verifyProof(): Boolean = Try {
    /* Sanity check of proof */
    if (proof.IBA.size != log) return false
    if (proof.Dk.size != log) return false
    if (proof.zwv.size != log) return false

    /* The size of unit vector has to be perfect power of 2. So pad unit vector with Enc(0,0) if it is necessary. */
    val uv = padUnitVector(unitVector).get

    val res1 = checkCommitments(proof.IBA, proof.zwv)
    val res2 = checkUnitVector(uv, proof.Dk, proof.zwv.map(_._1), proof.R)

    res1 && res2
  }.getOrElse(false)

  private def checkCommitments(IBA: Seq[(GroupElement, GroupElement, GroupElement)],
                               zwv: Seq[(BigInt, BigInt, BigInt)]): Boolean = {
    for (i <- 0 until log) {
      val (_I,_B,_A) = (IBA(i)._1, IBA(i)._2, IBA(i)._3)
      val (z,w,v) = (zwv(i)._1, zwv(i)._2, zwv(i)._3)

      /* 1 check (I^x * B == Com(z;w)) */
      val com = pedersenCommitment(crs, z, w).get
      val Ix = _I.pow(X).get
      val IxB = Ix.multiply(_B).get
      if (IxB != com) return false

      /* 2 check (I^(x-z)*A == Com(0,v) */
      val com2 = pedersenCommitment(crs, 0, v).get
      val p = (X - z).mod(dlog.groupOrder)
      val Ixz = _I.pow(p).get
      val IxzA = Ixz.multiply(_A).get
      if (IxzA != com2) return false
    }

    true
  }

  private def checkUnitVector(uv: Seq[ElGamalCiphertext],
                              Dk: Seq[ElGamalCiphertext],
                              z: Seq[BigInt],
                              R: BigInt): Boolean = {
    val x_pow_log = X.pow(log).mod(dlog.groupOrder)
    var mult1: ElGamalCiphertext = ElGamalCiphertext(dlog.groupIdentity, dlog.groupIdentity) // initializing acc with neutral elements

    for (i <- 0 until uvSize) {
      val idx = SHVZKCommon.intToBinArray(i, log)
      var multz = BigInt(1)
      for (j <- 0 until log) {
        val m = if (idx(j) == 1) z(j) else X - z(j)
        multz = (multz * m).mod(dlog.groupOrder)
      }
      val enc = LiftedElGamalEnc.encrypt(pubKey, 0, -multz).get
      val multC = uv(i).pow(x_pow_log).get
      val y_pow_i = Y.pow(i).mod(dlog.groupOrder)


      val t = (multC * enc).pow(y_pow_i).get
      mult1 = mult1 * t
    }

    var multD = Dk(0).pow(X.pow(0)).get
    for (i <- 1 until log) {
      val xpow = X.pow(i).mod(dlog.groupOrder)
      multD = multD * Dk(i).pow(xpow).get
    }

    val check = mult1 * multD
    val com = LiftedElGamalEnc.encrypt(pubKey, R, 0).get

    (check.c1 == com.c1) && (check.c2 == com.c2)
  }
}
