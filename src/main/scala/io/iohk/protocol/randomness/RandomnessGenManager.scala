package io.iohk.protocol.randomness

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalEnc}
import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.{ElgamalDecrNIZK, ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

import scala.util.Try

/*
* RandomnessManager encapsulates logic related to generation/decryption/validation of the randomness shares
*
*/
object RandomnessGenManager {

  private val SALT = BigInt("7ab67c1ee9376f9ab130", 16)

  /**
    * Generates randomness as a point on the curve. Note that an additional SALT is used to initialize
    * random number generator, it is a sefety measury in case a private key is used as a seed.
    *
    * @param ctx
    * @param seed a seed to initialize random generator
    * @return
    */
  def getRand(ctx: CryptoContext, seed: Array[Byte]): GroupElement = {
    import ctx.group
    val bytes = seed ++ SALT.toByteArray
    val rand = new FieldElementSP800DRNG(bytes, group.groupOrder).nextRand
    group.groupGenerator.pow(rand).get
  }

  /**
    * Generate encrypted randomness share. Basically randomness share is an encrypted randomness.
    *
    * @param ctx
    * @param pubKey personal pub key
    * @param msg randomness
    * @return
    */
  def encryptRandomnessShare(ctx: CryptoContext, pubKey: PubKey, msg: GroupElement): ElGamalCiphertext = {
    import ctx.group
    ElGamalEnc.encrypt(pubKey, msg).get._1
  }

  /**
    * Generate decrypted randomness share with a proof of correctness.
    *
    * @param ctx
    * @param privKey private key that was used to produce ciphertext
    * @param ciphertext encrypted share
    * @return
    */
  def decryptRandomnessShare(ctx: CryptoContext, privKey: PrivKey, ciphertext: ElGamalCiphertext): DecryptedRandomnessShare = {
    import ctx.{group,hash}
    val decryptedRandomness = ElGamalEnc.decrypt(privKey, ciphertext).get
    val proof = ElgamalDecrNIZK.produceNIZK(ciphertext, privKey).get
    DecryptedRandomnessShare(decryptedRandomness, proof)
  }

  /**
    * Validates that the decrypted share corresponds to the encrypted share by checkiing a proof
    *
    * @param ctx
    * @param pubKey pub key that was used to produce ciphertext
    * @param ciphertext encrypted randomness
    * @param decryptedShare decrypted randomness with zero-knowledge proof
    * @return
    */
  def validateDecryptedRandomnessShare(ctx: CryptoContext,
                                       pubKey: PubKey,
                                       ciphertext: ElGamalCiphertext,
                                       decryptedShare: DecryptedRandomnessShare): Boolean = {
    import ctx.{group,hash}
    ElgamalDecrNIZK.verifyNIZK(pubKey, ciphertext, decryptedShare.randomness, decryptedShare.proof)
  }
}

case class DecryptedRandomnessShare(randomness: GroupElement,
                                    proof: ElgamalDecrNIZKProof) extends BytesSerializable {

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
