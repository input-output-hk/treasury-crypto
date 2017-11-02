package treasury.crypto.nizk.shvzk

import java.math.BigInteger

import treasury.crypto._
import treasury.crypto.core._

class SHVZKCommon(val cs: Cryptosystem,
                  val pubKey: PubKey,
                  val unitVector: Seq[Ciphertext]) {

  protected val log = scala.math.ceil(SHVZKCommon.log2(unitVector.size)).toInt
  protected val uvSize = scala.math.pow(2, log).toInt

  /* Use hash of the statement as Common Reference String for both prover and verifier */
  protected val crs = new BigInteger({
    val bytes: Array[Byte] = unitVector.foldLeft(Array[Byte]()) {
      (acc, c) => acc ++ c._1.getEncoded(true) ++ c._2.getEncoded(true)
    }
    cs.hash256(pubKey.getEncoded(true) ++ bytes)
  })

  /* Fill in unit vector with Enc(0,0) elements so that its size is exactly the power of 2 (2^log) */
  def padUnitVector(uv: Seq[Ciphertext]): Seq[Ciphertext] = {
    if (uv.size == uvSize) uv
    else {
      val zeroUnit = cs.encrypt(pubKey, Zero, Zero)
      val paddingSize = (uvSize - unitVector.size).toInt

      val uvPadding = Array.fill[Ciphertext](paddingSize)(zeroUnit)

      unitVector ++ uvPadding
    }
  }

  /* Fill in rand vector with (0) elements so that its size is exactly the power of 2 (2^log) */
  def padRandVector(rand: Seq[Randomness]): Seq[Randomness] = {
    if (rand.size == uvSize) rand
    else {
      val paddingSize = (uvSize - unitVector.size).toInt
      val randPadding = Array.fill[Randomness](paddingSize)(Zero)

      rand ++ randPadding
    }
  }

  def pedersenCommitment(crs: BigInteger, m: Element, r: Randomness): Point = {
    val ck = cs.basePoint.multiply(crs)
    val c1 = cs.basePoint.multiply(m)
    val c2 = ck.multiply(r)

    c1.add(c2)
  }
}


object SHVZKCommon {
  def log2(x: Double) = scala.math.log10(x)/scala.math.log10(2.0)

  def intToBinArray(i: Int, digits: Int): Array[Byte] = {
    assert(i < scala.math.pow(2, digits))
    val bin = i.toBinaryString.map(s => if(s == '0') 0.toByte else 1.toByte).toArray
    if (bin.size == digits) bin
    else Array.fill[Byte](digits - bin.size)(0) ++ bin
  }
}
