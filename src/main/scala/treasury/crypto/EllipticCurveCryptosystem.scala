package treasury.crypto

import java.math.BigInteger
import java.security.{KeyPair, KeyPairGenerator, SecureRandom, Security}

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.{ECPrivateKey, ECPublicKey}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.math.ec.ECPoint

/**
  * Created by lpsun on 27.09.17.
  */
class EllipticCurveCryptosystem extends Cryptosystem {

  Security.addProvider(new BouncyCastleProvider())

  // secp256r1
//  val p = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
//  val a = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
//  val b = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
//  val Gx = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
//  val Gy = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
//  val n  = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
//  val h  = 1

//  val curve = new ECCurve.Fp(p, a, b);
//  val G = curve.decodePoint(Hex.decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"))
//  val ecSpec = new ECParameterSpec(curve, G, n);

  private val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
  private lazy val curve = ecSpec.getCurve
  private lazy val secureRandom = new SecureRandom()

  private val keyPairGenerator: KeyPairGenerator = {
    val g = KeyPairGenerator.getInstance("EC", "BC")
    g.initialize(ecSpec, secureRandom)
    g
  }

  def basePoint = ecSpec.getG.getEncoded(true)
  def orderOfBasePoint = ecSpec.getN

  def createKeyPair(): (PrivKey, PubKey) = {
    val pair: KeyPair = keyPairGenerator.generateKeyPair
    val publicKey = pair.getPublic.asInstanceOf[ECPublicKey]
    val privateKey = pair.getPrivate.asInstanceOf[ECPrivateKey]

    (privateKey.getD.toByteArray, publicKey.getQ.getEncoded(true))
  }

  def encrypt(pk: PubKey, rand: Randomness, msg: Int): Ciphertext = {
    encrypt(pk, rand, BigInt(msg).toByteArray)
  }

  def encrypt(pk: PubKey, rand: Randomness, msg: Array[Byte]): Ciphertext = {
    val pubKeyPoint = curve.decodePoint(pk)
    val r = new BigInteger(rand)
    val m = new BigInteger(msg)

    val rG = ecSpec.getG.multiply(r)
    val rPk = pubKeyPoint.multiply(r)
    val mG = ecSpec.getG.multiply(m)
    val mGrPk = mG.add(rPk)

    (rG.getEncoded(true), mGrPk.getEncoded(true))
  }

  def decrypt(pk: PrivKey, ciphertext: Ciphertext): Int = {
    val rG = curve.decodePoint(ciphertext._1)
    val mGrPk = curve.decodePoint(ciphertext._2)
    val privKey = new BigInteger(pk)

    val t = rG.multiply(privKey)
    val plaintext = mGrPk.subtract(t).normalize()

    reconstructMessage(plaintext)
  }

  def pedersenCommitment(crs: Array[Byte], m: Element, r: Randomness): Point = {
    val ck = ecSpec.getG.multiply(new BigInteger(crs))
    val c1 = ecSpec.getG.multiply(new BigInteger(m))
    val c2 = ck.multiply(new BigInteger(r))
    val comm = c1.add(c2)

    comm.getEncoded(true)
  }

  def getRand(): Randomness = {
    new BigInteger(orderOfBasePoint.bitLength, secureRandom).mod(orderOfBasePoint).toByteArray
  }

  def add(cipherText1: Ciphertext, cipherText2: Ciphertext): Ciphertext = {
    val C1_1 = curve.decodePoint(cipherText1._1)
    val C1_2 = curve.decodePoint(cipherText1._2)

    val C2_1 = curve.decodePoint(cipherText2._1)
    val C2_2 = curve.decodePoint(cipherText2._2)

    (C1_1.add(C2_1).getEncoded(true), C1_2.add(C2_2).getEncoded(true))
  }

  def add(point1: Point, point2: Point): Point = {
    val p1 = curve.decodePoint(point1)
    val p2 = curve.decodePoint(point2)

    p1.add(p2).getEncoded(true)
  }

  def multiply(point: Point, scalar: Element): Point = {
    val p = curve.decodePoint(point)
    val s = new BigInteger(scalar)

    p.multiply(s).getEncoded(true)
  }

  def multiply(cipherText: Ciphertext, scalar: Element): Ciphertext = {

    val C_1 = curve.decodePoint(cipherText._1)
    val C_2 = curve.decodePoint(cipherText._2)

    val scalarBigInt = new BigInteger(scalar)
    (C_1.multiply(scalarBigInt).getEncoded(true), C_2.multiply(scalarBigInt).getEncoded(true))
  }

  def multiplyScalars(scalar1: Element, scalar2: Element): Element = {
    val a = new BigInteger(scalar1)
    val b = new BigInteger(scalar2)

    a.multiply(b).mod(orderOfBasePoint).toByteArray
  }

  def hash256(bytes: Array[Byte]): Array[Byte] = {
    val md = new DigestSHA3(256)
    md.update(bytes)
    md.digest
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
  private def reconstructMessage(plaintextPoint: ECPoint): Int = {
    var P = ecSpec.getG

    if (P.multiply(new BigInteger("0")).equals(plaintextPoint))
      return 0

    if(P.equals(plaintextPoint))
      return 1

    /* msg is allowed in range 1 .. 2^31-1 */
    for (msg <- 2 to Integer.MAX_VALUE)
    {
      P = P.add(ecSpec.getG)
      if(P.equals(plaintextPoint))
        return msg
    }
    -1
  }
}
