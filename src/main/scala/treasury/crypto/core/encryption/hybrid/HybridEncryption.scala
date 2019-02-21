package treasury.crypto.core.encryption.hybrid

import treasury.crypto.core.encryption.elgamal.ElGamalEnc
import treasury.crypto.core.encryption.encryption.{PrivKey, PubKey}
import treasury.crypto.core.primitives.blockcipher.BlockCipher
import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, GroupElement}

import scala.util.Try

/*
* HybridEncryption implements a hybrid scheme where a message is encrypted by symmetric cipher (such as AES) while the
* key for symmetric cipher is encrypted with assymetric ElGamal scheme. Both encrypted message and encrypted symmetric key
* constitute a HybridCiphertext. The receiver provided with a private key for Elgamal scheme is able to decrypt the
* symmetric key and consequently an entire message.
* Such scheme allows efficient encryption of big messages without need to agree on shared symmetric key. Using pure
* ElGamal for big messages is quite problematic, cause it requires to map message into group elements and then encrypt
* them one at a time.
*
* Note that ElGamal encryption scheme requires message to be represented as a group element, so there should be
* a bidirectional mapping from symmetric key to a group element. In this implementation the random group element is
* generated in the first place and then symmetric key is derived from it (it is a bit easier then deriving group element
* from symmetric key).
*/
object HybridEncryption {

  /*
  * This method internally generates random group element and derives a symmetric key from it. The group element is then
  * encrypted and included to the ciphertext, so that the receiver can decrypt the group element, derive symmetric key
  * from it and then decrypt an entire message.
  */
  def encrypt(pubKey: PubKey, msg: Array[Byte])
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[HybridCiphertext] = {

    dlogGroup.createRandomGroupElement.flatMap { groupElement =>
      encrypt(pubKey, msg, groupElement)
    }
  }

  /*
  * This method accepts a secret seed as an argument. Secret seed is used to deterministically derive the group element
  * which will be used to produce symmetric key. The group element is then encrypted and included to the ciphertext,
  * so that the receiver can decrypt the group element, derive symmetric key from it and then decrypt an entire message.
  */
  def encrypt(pubKey: PubKey, msg: Array[Byte], secretSeed: Array[Byte])
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[HybridCiphertext] = {

    dlogGroup.createGroupElementFromSeed(secretSeed).flatMap { secretSeedAsGroupElement =>
      encrypt(pubKey, msg, secretSeedAsGroupElement)
    }
  }

  /*
  * This method accepts a group element as an argument. This group element serves as a secret seed to derive symmetric key.
  * The group element is then encrypted and included to the ciphertext,
  * so that the receiver can decrypt the group element, derive symmetric key from it and then decrypt an entire message.
  */
  def encrypt(pubKey: PubKey, msg: Array[Byte], secretSeedAsGroupElement: GroupElement)
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[HybridCiphertext] = Try {

    val symmetricKey = blockCipher.generateKey(secretSeedAsGroupElement.bytes)
    val ciphertext = blockCipher.encrypt(symmetricKey, msg).get
    val encryptedGroupElement = ElGamalEnc.encrypt(pubKey, secretSeedAsGroupElement).get._1

    HybridCiphertext(encryptedGroupElement, ciphertext)
  }

  /*
  * Decryption is done with using only the private key. First, a group element is decrypted with privKey, then the
  * symmetric key is derived from the group element. Finally, the message is decrypted with the symmetric key.
  */
  def decrypt(privKey: PrivKey, ciphertext: HybridCiphertext)
             (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher): Try[Array[Byte]] = {

    ElGamalEnc.decrypt(privKey, ciphertext.encryptedSymmetricKey).flatMap { secretSeedAsGroupElement =>
      val symmetricKey = blockCipher.generateKey(secretSeedAsGroupElement.bytes)
      blockCipher.decrypt(symmetricKey, ciphertext.encryptedMessage)
    }
  }
}
