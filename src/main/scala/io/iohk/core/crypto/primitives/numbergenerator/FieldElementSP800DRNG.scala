package io.iohk.core.crypto.primitives.numbergenerator

/*
  Generates a deterministic sequence of elements in Zp field, which depends on seed
 */
class FieldElementSP800DRNG(seed: Array[Byte], p: BigInt) {

  private val drng = new SP800DRNG(seed)
  private val byteSize = p.bitLength / 8 + 1;
  require(p > 0)

  def nextRand: BigInt = {
    val randBytes = drng.nextBytes(byteSize)
    BigInt(randBytes).mod(p)
  }
}
