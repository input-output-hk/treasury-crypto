package io.iohk.protocol.nizk

import com.google.common.primitives.{Bytes, Shorts}
import io.iohk.core.crypto.encryption._
import io.iohk.core.crypto.encryption.hybrid.dlp.DLPHybridCiphertext
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.core.crypto.primitives.numbergenerator.SP800DRNG
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

/**
  * The DLPHybridDecrNIZK allows to verify that the "ciphertext" is an encryption of the "plaintext" that was done with the DLPHybridEncryption scheme,
  * where (privKey, pubKey) constitutes a valid key pair
  */
object DLPHybridDecrNIZK {

  def produceNIZK(ciphertext: DLPHybridCiphertext, privKey: PrivKey)
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[DLPHybridDecrNIZKProof] = Try {

    //val randomness = dlogGroup.createRandomNumber
    // TODO: we need deterministic proofs (for DKG stuff). Is it secure to do it this way?
    // TODO: Seems like yes if the algorithm is not used twice with the same input params. If it does
    // TODO: then it will leak relevance between two proofs because the they would be the same. But this should be fine and maybe even useful.
    // TODO: Actually determinism is not really needed, but some DKG unit tests rely on this property.
    val randomness = BigInt(new SP800DRNG(privKey.toByteArray ++ ciphertext.bytes).nextBytes(128))

    val pubKey = dlogGroup.groupGenerator.pow(privKey).get
    val decryptedKey = ciphertext.encryptedKey.pow(privKey).get
    val dleqProof = DLEQStandardNIZK.produceNIZK(
      H1 = pubKey, H2 = decryptedKey, G1 = dlogGroup.groupGenerator, G2 = ciphertext.encryptedKey,
      privKey, Option(randomness)).get

    DLPHybridDecrNIZKProof(decryptedKey, dleqProof)
  }

  def verifyNIZK(pubKey: PubKey, ciphertext: DLPHybridCiphertext, decryptedMessage: Array[Byte], proof: DLPHybridDecrNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher, hashFunction: CryptographicHash): Boolean = Try {

    val symmetricKey = blockCipher.generateKey(proof.decryptedKey.bytes)
    val c = blockCipher.encrypt(symmetricKey, decryptedMessage).get
    c.bytes.sameElements(ciphertext.encryptedMessage.bytes) &&
    DLEQStandardNIZK.verifyNIZK(pubKey, proof.decryptedKey, dlogGroup.groupGenerator, ciphertext.encryptedKey, proof.dleqProof)
  }.getOrElse(false)
}

case class DLPHybridDecrNIZKProof(decryptedKey: GroupElement, dleqProof: DLEQStandardNIZKProof) extends BytesSerializable {

  override type M = DLPHybridDecrNIZKProof
  override type DECODER = DiscreteLogGroup
  override val serializer = DLPHybridDecrNIZKProofSerializer

  def size: Int = bytes.length
}

object DLPHybridDecrNIZKProofSerializer extends Serializer[DLPHybridDecrNIZKProof, DiscreteLogGroup] {

  override def toBytes(obj: DLPHybridDecrNIZKProof): Array[Byte] = {
    val keyBytes = obj.decryptedKey.bytes
    val dleqBytes = obj.dleqProof.bytes

    Bytes.concat(Array(keyBytes.length.toByte), keyBytes,
      Shorts.toByteArray(dleqBytes.length.toShort), dleqBytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[DLPHybridDecrNIZKProof] = Try {
    val group = decoder.get
    val keyLen = bytes(0)
    val key = group.reconstructGroupElement(bytes.slice(1,keyLen+1)).get
    val pos = keyLen + 1

    val dleqLen = Shorts.fromByteArray(bytes.slice(pos,pos+2))
    val dleqProof = DLEQStandardNIZKProofSerializer.parseBytes(bytes.slice(pos+2,dleqLen+pos+2), decoder).get

    DLPHybridDecrNIZKProof(key, dleqProof)
  }
}
