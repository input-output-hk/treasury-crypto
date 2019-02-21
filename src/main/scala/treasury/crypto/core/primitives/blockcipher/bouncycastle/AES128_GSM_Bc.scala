package treasury.crypto.core.primitives.blockcipher.bouncycastle

import java.security.{SecureRandom, Security}

import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import treasury.crypto.core.primitives.blockcipher.BlockCipher.SecretKey
import treasury.crypto.core.primitives.blockcipher._
import treasury.crypto.core.primitives.hash.CryptographicHashFactory
import treasury.crypto.core.primitives.hash.CryptographicHashFactory.AvailableHashes
import treasury.crypto.core.primitives.hash.bouncycastle.SHA3_256_HashBc
import treasury.crypto.core.primitives.numbergenerator.SP800DRNG

import scala.util.Try

object AES128_GSM_Bc extends AES128_GSM {

  Security.addProvider(new BouncyCastleProvider())
  private lazy val secureRandom = new SecureRandom
  private val KEY_SIZE = 32 // 16 bytes of key and 16 bytes of initialization vector

  override def generateKey: BlockCipher.SecretKey = {
    val keyMaterial = new Array[Byte](keySize)
    secureRandom.nextBytes(keyMaterial)
    AESSecretKey(keyMaterial)
  }

  override def generateKey(seed: Array[Byte]): BlockCipher.SecretKey = {
    val keyMaterial = new SP800DRNG(seed).nextBytes(keySize)
    AESSecretKey(keyMaterial)
  }

  override def keySize: Int = KEY_SIZE

  override def encrypt(key: SecretKey, msg: Array[Byte]): Try[AESCiphertext] = Try {
    val keyMaterial = key.asInstanceOf[AESSecretKey].key
    computeBlock(keyMaterial, msg, Cipher.ENCRYPT_MODE).map(AESCiphertext(_)).get
  }

  override def decrypt(key: SecretKey, ciphertext: BlockCipher.Ciphertext): Try[Array[Byte]] = Try {
    val keyMaterial = key.asInstanceOf[AESSecretKey].key
    val aesCiphertext = ciphertext.asInstanceOf[AESCiphertext]
    computeBlock(keyMaterial, aesCiphertext.ciphertext, Cipher.DECRYPT_MODE).get
  }

  private def computeBlock(keyMaterial: Array[Byte], data: Array[Byte], mode: Int): Try[Array[Byte]] = Try {
    require(keyMaterial.length == keySize)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
    val key = keyMaterial.slice(0, keyMaterial.length / 2)
    val iv =  keyMaterial.slice(keyMaterial.length / 2, keyMaterial.length)

    cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
    cipher.doFinal(data)
  }
}
