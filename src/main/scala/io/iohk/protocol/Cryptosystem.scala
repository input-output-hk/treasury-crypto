package io.iohk.protocol

import java.math.BigInteger
import java.security.SecureRandom

import io.iohk.core._
import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.{ElGamalEnc, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.hybrid.{HybridCiphertext, HybridEncryption, HybridPlaintext}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroupFactory, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes

/* Holds common params for Elliptic Curve cryptosystem that are used throughout the library
*/
class Cryptosystem {

//  Security.addProvider(new BouncyCastleProvider())
//
//  private val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
//  private lazy val curve = ecSpec.getCurve
  private lazy val secureRandom = new SecureRandom()
//
//  private val keyPairGenerator: KeyPairGenerator = {
//    val g = KeyPairGenerator.getInstance("EC", "BC")
//    g.initialize(ecSpec, secureRandom)
//    g
//  }

  implicit val group = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  implicit val hash = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  implicit val blockCipher = BlockCipherFactory.constructBlockCipher(AvailableBlockCiphers.AES128_BSM_Bc).get

  def basePoint: GroupElement = group.groupGenerator
  def orderOfBasePoint: BigInt = group.groupOrder
  def infinityPoint: GroupElement = group.groupIdentity

  def createKeyPair: (PrivKey, PubKey) = encryption.createKeyPair.get

  /* Implements Elliptic Curve version of Lifted ElGamal encryption.
  *  A plaintext is represented as BigInteger.
  * */
  def encrypt(pubKey: PubKey, rand: Randomness, msg: BigInteger): Ciphertext = {
    LiftedElGamalEnc.encrypt(pubKey, rand, BigInt(msg)).get
  }

  /* Implements Elliptic Curve version of Lifted ElGamal decryption.
  *  A plaintext is represented as BigInteger. It is reconstructed by solving DLOG.
  * */
  def decrypt(privKey: PrivKey, ciphertext: Ciphertext): BigInteger = {
    LiftedElGamalEnc.decrypt(privKey, ciphertext).get.bigInteger
  }

  /* Implements Elliptic Curve version of classic ElGamal encryption.
  *  A plaintext is represented as point on the curve.
  * */
  def encryptPoint(pubKey: PubKey, rand: Randomness, msg: Point): Ciphertext = {
    ElGamalEnc.encrypt(pubKey, rand, msg).get
  }

  /* Implements Elliptic Curve version of classic ElGamal decryption.
  *  A plaintext is represented as point on the curve.
  * */
  def decryptPoint(privKey: PrivKey, ciphertext: Ciphertext): Point = {
    ElGamalEnc.decrypt(privKey, ciphertext).get
  }

//  private def aesEncryptDecrypt(msg: Array[Byte], keyMaterial: Array[Byte], mode: Int): Array[Byte] = {
//
//    assert(keyMaterial.length == 32)
//
//    val key = keyMaterial.slice(0, keyMaterial.length / 2)
//    val iv =  keyMaterial.slice(keyMaterial.length / 2, keyMaterial.length)
//
//    val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
//
//    cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
//    cipher.doFinal(msg)
//  }

//  def hybridEncrypt(pubKey: PubKey, msg: Array[Byte], secretSeed: Array[Byte], symmetricKey: Option[Point] = None): HybridCiphertext = {
//    symmetricKey.map { groupElement =>
//      HybridEncryption.encrypt(pubKey, msg, groupElement).get
//    }.getOrElse {
//      HybridEncryption.encrypt(pubKey, msg, secretSeed).get
//    }
//  }
//
//  def hybridDecrypt(privKey: PrivKey, ciphertext: HybridCiphertext): HybridPlaintext = {
//    HybridEncryption.decrypt(privKey, ciphertext).get
//  }

  // Pseudorandom number generation in Zp field (p = orderOfBasePoint)
  def getRand: Randomness = {
    group.createRandomNumber
  }

  def getRandBytes(size: Int): Array[Byte] = {
    val bytes = new Array[Byte](size)
    secureRandom.nextBytes(bytes)
    bytes
  }

  def add(cipherText1: Ciphertext, cipherText2: Ciphertext): Ciphertext = {
    cipherText1.multiply(cipherText2).get
  }

  def multiply(cipherText: Ciphertext, scalar: Element): Ciphertext = {
    cipherText.pow(scalar).get
  }

  def hash256(bytes: Array[Byte]): Array[Byte] = {
    hash.hash(bytes)
  }

  def decodePoint(point: Array[Byte]): Point = {
    group.reconstructGroupElement(point).get
  }
}
