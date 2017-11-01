package treasury.crypto

import java.math.BigInteger
import java.security.{KeyPair, KeyPairGenerator, SecureRandom, Security}

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.{ECPrivateKey, ECPublicKey}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.math.ec.ECPoint

/* Holds common params for Elliptic Curve cryptosystem that are used throughout the library
*/
class Cryptosystem {

  Security.addProvider(new BouncyCastleProvider())

  private val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
  private lazy val curve = ecSpec.getCurve
  private lazy val secureRandom = new SecureRandom()

  private val keyPairGenerator: KeyPairGenerator = {
    val g = KeyPairGenerator.getInstance("EC", "BC")
    g.initialize(ecSpec, secureRandom)
    g
  }

  def basePoint = ecSpec.getG
  def orderOfBasePoint = ecSpec.getN
  def infinityPoint = ecSpec.getCurve.getInfinity

  def createKeyPair(): (PrivKey, PubKey) = {
    val pair: KeyPair = keyPairGenerator.generateKeyPair
    val publicKey = pair.getPublic.asInstanceOf[ECPublicKey]
    val privateKey = pair.getPrivate.asInstanceOf[ECPrivateKey]

    (privateKey.getD, publicKey.getQ)
  }

  def encrypt(pubKey: PubKey, rand: Randomness, msg: BigInteger): Ciphertext = {
    val rG = ecSpec.getG.multiply(rand)
    val rPk = pubKey.multiply(rand)
    val mG = ecSpec.getG.multiply(msg)
    val mGrPk = mG.add(rPk)

    (rG, mGrPk)
  }

  def decrypt(privKey: PrivKey, ciphertext: Ciphertext): BigInteger = {
    val rG = ciphertext._1
    val mGrPk = ciphertext._2

    val t = rG.multiply(privKey)
    val plaintext = mGrPk.subtract(t).normalize()

    reconstructMessage(plaintext)
  }

  def getRand(): Randomness = {
    new BigInteger(orderOfBasePoint.bitLength, secureRandom).mod(orderOfBasePoint)
  }

  def add(cipherText1: Ciphertext, cipherText2: Ciphertext): Ciphertext = {
    (cipherText1._1.add(cipherText2._1), cipherText1._2.add(cipherText2._2))
  }

  def multiply(cipherText: Ciphertext, scalar: Element): Ciphertext = {
    (cipherText._1.multiply(scalar), cipherText._2.multiply(scalar))
  }

  def hash256(bytes: Array[Byte]): Array[Byte] = {
    val md = new DigestSHA3(256)
    md.update(bytes)
    md.digest
  }

  def decodePoint(point: Array[Byte]): ECPoint = {
    curve.decodePoint(point)
  }

  /* TODO: Conversion algorithm (msg -> ECPoint) should be implemented.
   * Currently it is a stub that returns a constant point on the curve. */
  private def msgToPoint(msg: Int): ECPoint = {
    ecSpec.getCurve.createPoint(
      new BigInteger("fc648429e72021c5f9694ebbbecd920802e7356d84711f8962a0a38270f4ecfd", 16),
      new BigInteger("b54f04e7ffea143d639857295cc7989d4ee998314ef5c0d6e3d6f27ad6252da7", 16)
    )
  }

  /* Solve discrete logarithm for m*G */
  private def reconstructMessage(plaintextPoint: ECPoint): BigInteger = {
    var P = ecSpec.getG

    if (P.multiply(Zero).equals(plaintextPoint))
      return Zero

    if(P.equals(plaintextPoint))
      return One

    /* msg is allowed in range 1 .. 2^31-1 */
    for (msg <- 2 to Integer.MAX_VALUE)
    {
      P = P.add(ecSpec.getG)
      if(P.equals(plaintextPoint))
        return BigInteger.valueOf(msg)
    }
    BigInteger.valueOf(-1)
  }
}