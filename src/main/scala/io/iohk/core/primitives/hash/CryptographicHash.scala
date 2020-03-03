package io.iohk.core.primitives.hash

trait CryptographicHash {

  def algorithmName: String

  /*
  * Returns the size of the hashed message in bytes
  */
  def digestSize: Int

  /*
    Hashes an input of arbitrary size and produces an output of the size digestSize
   */
  def hash(input: Array[Byte]): Array[Byte]
}
