package treasury.crypto.decryption

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.nizk.{ElgamalDecrNIZK, ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

import scala.util.Try

/*
* RandomnessManager encapsulates logic related to generation/decryption/validation of the seed shares
*
*/
object SeedGenManager {

  private val SALT = new BigInteger("7ab67c1ee9376f9ab130", 16)

  /**
    * Generates randomness as a point on the curve. Note that an additional SALT is used to initialize
    * random number generator, it is a sefety measury in case a private key is used as a seed.
    *
    * @param cs
    * @param seed a seed to initialize random generator
    * @return
    */
  def getRand(cs: Cryptosystem, seed: Array[Byte]): Point = {
    val bytes = seed ++ SALT.toByteArray
    val rand = DRNG(bytes, cs).getRand
    cs.basePoint.multiply(rand)
  }

  /**
    * Generate encrypted seed share. Basically seed share is an encrypted randomness.
    *
    * @param cs
    * @param pubKey personal pub key
    * @param msg randomness
    * @return
    */
  def encryptSeedShare(cs: Cryptosystem, pubKey: PubKey, msg: Point): Ciphertext = {
    cs.encryptPoint(pubKey: PubKey, cs.getRand, msg)
  }

  /**
    * Generate decrypted seed share with a proof of correctness.
    *
    * @param cs
    * @param privKey private key that was used to produce ciphertext
    * @param ciphertext encrypted share
    * @return
    */
  def decryptSeedShare(cs: Cryptosystem, privKey: PrivKey, ciphertext: Ciphertext): DecryptedSeedShare = {
    val decryptedSeed = cs.decryptPoint(privKey, ciphertext)
    val proof = ElgamalDecrNIZK.produceNIZK(cs, ciphertext, privKey)
    DecryptedSeedShare(decryptedSeed, proof)
  }

  /**
    * Validates that the decrypted share corresponds to the encrypted share by checkiing a proof
    *
    * @param cs
    * @param pubKey pub key that was used to produce ciphertext
    * @param ciphertext encrypted seed
    * @param decryptedShare decrypted seed with zero-knowledge proof
    * @return
    */
  def validateDecryptedSeedShare(cs: Cryptosystem, pubKey: PubKey, ciphertext: Ciphertext, decryptedShare: DecryptedSeedShare): Boolean = {
    ElgamalDecrNIZK.verifyNIZK(cs, pubKey, ciphertext, decryptedShare.seed, decryptedShare.proof)
  }
}

case class DecryptedSeedShare(seed: Point, proof: ElgamalDecrNIZKProof) extends BytesSerializable {

  override type M = DecryptedSeedShare
  override val serializer = DecryptedSeedShareSerializer

  def size: Int = bytes.length
}

object DecryptedSeedShareSerializer extends Serializer[DecryptedSeedShare] {

  override def toBytes(obj: DecryptedSeedShare): Array[Byte] = {
    val seedBytes = obj.seed.getEncoded(true)
    Bytes.concat(Ints.toByteArray(seedBytes.length), seedBytes, obj.proof.bytes)
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[DecryptedSeedShare] = Try {
    val seedBytesLen = Ints.fromByteArray(bytes.slice(0, 4))
    val seed = cs.decodePoint(bytes.slice(4, 4 + seedBytesLen))
    val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes.drop(4 + seedBytesLen), cs).get
    DecryptedSeedShare(seed, proof)
  }
}
