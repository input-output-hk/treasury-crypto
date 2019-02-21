package treasury.crypto.core.encryption.hybrid

import treasury.crypto.core.Cryptosystem
import treasury.crypto.core.encryption.elgamal.ElGamalCiphertext
import treasury.crypto.core.primitives.blockcipher.BlockCipher
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class HybridCiphertext(encryptedSymmetricKey: ElGamalCiphertext, encryptedMessage: BlockCipher.Ciphertext)
  extends BytesSerializable {

  override type M = HybridCiphertext
  override val serializer: Serializer[M] = HybridCiphertextSerializer

  def size: Int = bytes.length
}

object HybridCiphertextSerializer extends Serializer[HybridCiphertext] {

  override def toBytes(obj: HybridCiphertext): Array[Byte] = { ???
//    Bytes.concat(
//      CiphertextSerizlizer.toBytes(obj.encryptedKey),
//      Ints.toByteArray(obj.encryptedMessage.length),
//      obj.encryptedMessage
//    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[HybridCiphertext] = Try { ???
//    val offset = IntAccumulator(0)
//
//    val encryptedKey = CiphertextSerizlizer.parseBytes(bytes, cs).get
//    offset.plus(CiphertextSerizlizer.toBytes(encryptedKey).length)
//
//    val encryptedMessageLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
//    val encryptedMessage = bytes.slice(offset.value, offset.plus(encryptedMessageLen))
//
//    HybridCiphertext(encryptedKey, encryptedMessage)
  }
}