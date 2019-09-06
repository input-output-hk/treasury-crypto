package treasury.crypto.decryption

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core._
import treasury.crypto.core.encryption.elgamal.ElGamalEnc
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.primitives.hash.CryptographicHash
import treasury.crypto.core.primitives.numbergenerator.SP800DRNG
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
  def getRand(seed: Array[Byte])
             (implicit dlogGroup: DiscreteLogGroup): Point = {
    val bytes = seed ++ SALT.toByteArray
    val randBytes = new SP800DRNG(bytes).nextBytes(32)
    val rand = new BigInteger(randBytes).mod(dlogGroup.groupOrder)
    dlogGroup.groupGenerator.pow(rand).get
  }

  /**
    * Generate encrypted randomness share. Basically randomness share is an encrypted randomness.
    *
    * @param cs
    * @param pubKey personal pub key
    * @param msg randomness
    * @return
    */
  def encryptRandomnessShare(pubKey: PubKey, msg: Point)
                            (implicit dlogGroup: DiscreteLogGroup): Ciphertext = {
    ElGamalEnc.encrypt(pubKey, msg).get._1
  }

  /**
    * Generate decrypted randomness share with a proof of correctness.
    *
    * @param cs
    * @param privKey private key that was used to produce ciphertext
    * @param ciphertext encrypted share
    * @return
    */
  def decryptRandomnessShare(privKey: PrivKey, ciphertext: Ciphertext)
                            (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): DecryptedRandomnessShare = {
    val decryptedRandomness = ElGamalEnc.decrypt(privKey, ciphertext).get
    val proof = ElgamalDecrNIZK.produceNIZK(ciphertext, privKey).get
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
  def validateDecryptedRandomnessShare(pubKey: PubKey, ciphertext: Ciphertext, decryptedShare: DecryptedRandomnessShare)
                                      (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = {
    ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decryptedShare.randomness, decryptedShare.proof)
  }
}

case class DecryptedRandomnessShare(randomness: Point, proof: ElgamalDecrNIZKProof) extends BytesSerializable {

  override type M = DecryptedRandomnessShare
  override type DECODER = DiscreteLogGroup
  override val serializer = DecryptedRandomnessShareSerializer

  def size: Int = bytes.length
}

object DecryptedRandomnessShareSerializer extends Serializer[DecryptedRandomnessShare, DiscreteLogGroup] {

  override def toBytes(obj: DecryptedRandomnessShare): Array[Byte] = {
    val randomnessBytes = obj.randomness.bytes
    Bytes.concat(Ints.toByteArray(randomnessBytes.length), randomnessBytes, obj.proof.bytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[DecryptedRandomnessShare] = Try {
    val group = decoder.get
    val randomnessBytesLen = Ints.fromByteArray(bytes.slice(0, 4))
    val randomness = group.reconstructGroupElement(bytes.slice(4, 4 + randomnessBytesLen)).get
    val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes.drop(4 + randomnessBytesLen), decoder).get
    DecryptedRandomnessShare(randomness, proof)
  }
}
