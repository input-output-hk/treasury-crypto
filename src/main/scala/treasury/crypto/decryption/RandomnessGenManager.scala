package treasury.crypto.decryption

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.nizk.{ElgamalDecrNIZK, ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

import scala.util.Try

/*
* RandomnessManager encapsulates logic related to generation/decryption/validation of the randomness shares
*
*/
object RandomnessGenManager {

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
    * Generate encrypted randomness share. Basically randomness share is an encrypted randomness.
    *
    * @param cs
    * @param pubKey personal pub key
    * @param msg randomness
    * @return
    */
  def encryptRandomnessShare(cs: Cryptosystem, pubKey: PubKey, msg: Point): Ciphertext = {
    cs.encryptPoint(pubKey: PubKey, cs.getRand, msg)
  }

  /**
    * Generate decrypted randomness share with a proof of correctness.
    *
    * @param cs
    * @param privKey private key that was used to produce ciphertext
    * @param ciphertext encrypted share
    * @return
    */
  def decryptRandomnessShare(cs: Cryptosystem, privKey: PrivKey, ciphertext: Ciphertext): DecryptedRandomnessShare = {
    val decryptedRandomness = cs.decryptPoint(privKey, ciphertext)
    val proof = ElgamalDecrNIZK.produceNIZK(cs, ciphertext, privKey)
    DecryptedRandomnessShare(decryptedRandomness, proof)
  }

  /**
    * Validates that the decrypted share corresponds to the encrypted share by checkiing a proof
    *
    * @param cs
    * @param pubKey pub key that was used to produce ciphertext
    * @param ciphertext encrypted randomness
    * @param decryptedShare decrypted randomness with zero-knowledge proof
    * @return
    */
  def validateDecryptedRandomnessShare(cs: Cryptosystem, pubKey: PubKey, ciphertext: Ciphertext, decryptedShare: DecryptedRandomnessShare): Boolean = {
    ElgamalDecrNIZK.verifyNIZK(cs, pubKey, ciphertext, decryptedShare.randomness, decryptedShare.proof)
  }
}

case class DecryptedRandomnessShare(randomness: Point, proof: ElgamalDecrNIZKProof) extends BytesSerializable {

  override type M = DecryptedRandomnessShare
  override val serializer = DecryptedRandomnessShareSerializer

  def size: Int = bytes.length
}

object DecryptedRandomnessShareSerializer extends Serializer[DecryptedRandomnessShare] {

  override def toBytes(obj: DecryptedRandomnessShare): Array[Byte] = {
    val randomnessBytes = obj.randomness.getEncoded(true)
    Bytes.concat(Ints.toByteArray(randomnessBytes.length), randomnessBytes, obj.proof.bytes)
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[DecryptedRandomnessShare] = Try {
    val randomnessBytesLen = Ints.fromByteArray(bytes.slice(0, 4))
    val randomness = cs.decodePoint(bytes.slice(4, 4 + randomnessBytesLen))
    val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes.drop(4 + randomnessBytesLen), cs).get
    DecryptedRandomnessShare(randomness, proof)
  }
}
