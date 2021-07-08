package io.iohk.core.crypto.encryption.hybrid.dlp

import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup

import scala.util.Try

/*
* DLPHybridEncryption implements a hybrid scheme where a message is encrypted by a symmetric block cipher (such as AES) while the
* key for the symmetric cipher is encrypted with an asymmetric scheme. In this version as an asymmetric scheme a DLP-based protocol is used.
* Both encrypted message and encrypted symmetric key constitute a HybridCiphertext.
* The receiver provided with a secret key for the asymmetric scheme is able to decrypt the symmetric key and consequently the entire message.
*/
object DLPHybridEncryption {

  /*
  * The method internally generates random field element needed to encrypt the symmetric key.
  */
  def encrypt(pubKey: PubKey, msg: Array[Byte])
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[DLPHybridCiphertext] = {
    encrypt(pubKey, msg, dlogGroup.createRandomNumber)
  }

  /*
  * This method accepts a secret seed as an argument. Secret seed is used to deterministically derive the field element
  * needed to encrypt the symmetric key.
  */
  def encrypt(pubKey: PubKey, msg: Array[Byte], secretSeed: Array[Byte])
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[DLPHybridCiphertext] = {
    val r = dlogGroup.createRandomNumberFromSeed(secretSeed)
    encrypt(pubKey, msg, r)
  }

  /*
  * This method accepts a field element as an argument. The field element serves as a secret to encrypt the symmetric key.
  */
  def encrypt(pubKey: PubKey, msg: Array[Byte], r: BigInt)
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[DLPHybridCiphertext] = Try {

    val C1 = dlogGroup.groupGenerator.pow(r).get
    val C2 = pubKey.pow(r).get
    val k = blockCipher.generateKey(C2.bytes)
    val encryptedMessage = blockCipher.encrypt(k, msg).get

    DLPHybridCiphertext(C1, encryptedMessage)
  }

  def decrypt(privKey: PrivKey, ciphertext: DLPHybridCiphertext)
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[Array[Byte]] = {
    ciphertext.encryptedKey.pow(privKey).flatMap { C2 =>
      val k = blockCipher.generateKey(C2.bytes)
      blockCipher.decrypt(k, ciphertext.encryptedMessage)
    }
  }
}
