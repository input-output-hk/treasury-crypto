package treasury.crypto

trait Cryptosystem {

  def createKeyPair(): (PrivKey, PubKey)

  /*
  * Produce a ciphertext consisting of two values: e = (e1, e2) = (g^r, g^m*pk^r)
  */
  def encrypt(pk: PubKey, r: Randomness, message: Int): Ciphertext
  def encrypt(pk: PubKey, r: Randomness, message: Array[Byte]): Ciphertext

  /*
  * Decrypts ciphertext and solve DLP for g^m to extract message
  */
  def decrypt(sk: PrivKey, ciphertext: Ciphertext): Int

  def getRand(): Randomness

  def add(cipherText1: Ciphertext, cipherText2: Ciphertext): Ciphertext

  def add(point1: Point, point2: Point): Point

  def multiply(point: Point, scalar: Element): Point

  def multiply(cipherText: Ciphertext, scalar: Element): Ciphertext

  def multiplyScalars(scalar1: Element, scalar2: Element): Element

  def hash256(bytes: Array[Byte]): Array[Byte]
}
