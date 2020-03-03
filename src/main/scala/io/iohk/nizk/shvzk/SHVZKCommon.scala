package io.iohk.nizk.shvzk

import java.math.BigInteger

import io.iohk.core.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.encryption.{PubKey, Randomness}
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.primitives.hash.CryptographicHash

import scala.util.Try

class SHVZKCommon(pubKey: PubKey, unitVector: Seq[ElGamalCiphertext])
                 (implicit val dlog: DiscreteLogGroup, implicit val hashFunction: CryptographicHash){

  require(hashFunction.digestSize >= 32)

  protected val log = scala.math.ceil(SHVZKCommon.log2(unitVector.size)).toInt
  protected val uvSize = scala.math.pow(2, log).toInt

  /* Use hash of the statement as Common Reference String for both prover and verifier */
  protected val crs = new BigInteger({
    val bytes: Array[Byte] = unitVector.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c.c1.bytes ++ c.c2.bytes
    }
    hashFunction.hash(pubKey.bytes ++ bytes)
  })

  /* Fill in unit vector with Enc(0,0) elements so that its size is exactly the power of 2 (2^log) */
  def padUnitVector(uv: Seq[ElGamalCiphertext]): Try[Seq[ElGamalCiphertext]] = Try {
    if (uv.size == uvSize) uv
    else {
      val zeroUnit = LiftedElGamalEnc.encrypt(pubKey, 0, 0).get
      val paddingSize = (uvSize - unitVector.size).toInt

      val uvPadding = Array.fill[ElGamalCiphertext](paddingSize)(zeroUnit)

      unitVector ++ uvPadding
    }
  }

  /* Fill in rand vector with (0) elements so that its size is exactly the power of 2 (2^log) */
  def padRandVector(rand: Seq[Randomness]): Seq[Randomness] = {
    if (rand.size == uvSize) rand
    else {
      val paddingSize = (uvSize - unitVector.size).toInt
      val randPadding = Array.fill[Randomness](paddingSize)(0)

      rand ++ randPadding
    }
  }

  def pedersenCommitment(crs: BigInt, m: BigInt, r: Randomness): Try[GroupElement] = Try {
    val ck = dlog.groupGenerator.pow(crs).get
    val c1 = dlog.groupGenerator.pow(m).get
    val c2 = ck.pow(r)

    c1.multiply(c2).get
  }
}

object SHVZKCommon {
  def log2(x: Double): Double = scala.math.log10(x)/scala.math.log10(2.0)

  def intToBinArray(i: Int, digits: Int): Array[Byte] = {
    require(i < scala.math.pow(2, digits))
    val bin = i.toBinaryString.map(s => if(s == '0') 0.toByte else 1.toByte).toArray
    if(bin.length == digits) bin
    else Array.fill[Byte](digits - bin.length)(0) ++ bin
  }
}
