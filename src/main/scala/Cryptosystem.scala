import java.security.SecureRandom
import common._

trait Cryptosystem {

  def createKeyPair(): (PrivKey, PubKey)

  /*
  * Produce a ciphertext consisting of two values: e = (e1, e2) = (g^r, g^m*pk^r)
  */
  def encrypt(pk: PubKey, r: Randomness, message: Message): Ciphertext

  /*
  * Decrypts ciphertext and solve DLP for g^m to extract message
  */
  def decrypt(sk: PrivKey, ciphertext: Ciphertext): Message

  def getRand(): Randomness

  def multiply(arg1: Ciphertext, arg2: Ciphertext): Ciphertext
}
