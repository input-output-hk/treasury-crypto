package treasury.crypto.core.primitives.numbergenerator

/*
 A basic interface for a random number generator
 */
trait RandomNumberGenerator {

  def algorithmName: String

  /*
   * @param  length    the size of the array that should be generated
   * @return           an array of random bytes of size length
  */
  def nextBytes(length: Int): Array[Byte]
}
