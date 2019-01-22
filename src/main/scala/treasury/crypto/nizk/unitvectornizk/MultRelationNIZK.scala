package treasury.crypto.nizk.unitvectornizk

import java.math.BigInteger

import treasury.crypto.core
import treasury.crypto.core._

/* MultRelationNIZK implements non-interactive zero knowledge protocol to prove a multiplicative relation between
 * two encrypted vectors.
 * Given an encrypted unit vector U and an encrypted value C, the protocol allows to prove that another encrypted
 * vector V contains elements from U multiplied by the value encrypted in C.
 */

object MultRelationNIZK {

  case class MultRelationNIZKProof(X: Ciphertext, Z: Ciphertext, x: Element, y: Element, z: Element)

  /**
    * @param encryptedValue An encrypted value
    * @param unitVector (witness) a plain unit vector
    * @param unitVectorRandomness (witness) an arrray of random values that were used to encrypt unit vector
    * @param zeroVectorRandomness (witness) an arrray of random values that were used to encrypt zero vector (which is
    *                             needed to produce V)
    * @return MultRelationNIZKProof
    */
  def produceNIZK(
                   cs: Cryptosystem,
                   pubKey: PubKey,
                   encryptedValue: Ciphertext,
                   unitVector: Seq[BigInteger],
                   unitVectorRandomness: Seq[Randomness],
                   zeroVectorRandomness: Seq[Randomness]
                 ): MultRelationNIZKProof = {
    require(unitVector.size == unitVectorRandomness.size)
    require(unitVector.size == zeroVectorRandomness.size)
    require(unitVector.filter(_.equals(core.One)).size == 1)
    require(unitVector.filter(_.equals(core.Zero)).size == (unitVector.size - 1))

    val x = cs.getRand
    val y = cs.getRand
    val z = cs.getRand

    val X = cs.encrypt(pubKey, y, x)
    val Z = cs.add(cs.multiply(encryptedValue, x), cs.encrypt(pubKey, z, core.Zero))

    val challenge = new BigInteger(
      cs.hash256 {
        pubKey.getEncoded(true) ++
        encryptedValue._1.getEncoded(true) ++
        encryptedValue._2.getEncoded(true) ++
        X._1.getEncoded(true) ++
        X._2.getEncoded(true) ++
        Z._1.getEncoded(true) ++
        Z._2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val uvIndex = unitVector.indexOf(core.One)
    val x_ = x.add(challenge.pow(uvIndex+1)).mod(cs.orderOfBasePoint)

    val rSum = unitVectorRandomness.zipWithIndex.foldLeft(core.Zero) { case (acc, (r,i)) =>
      acc.add(r.multiply(challenge.pow(i+1)))
    }
    val y_ = y.add(rSum).mod(cs.orderOfBasePoint)

    val tSum = zeroVectorRandomness.zipWithIndex.foldLeft(core.Zero) { case (acc, (t,i)) =>
      acc.add(t.multiply(challenge.pow(i+1)))
    }
    val z_ = z.add(tSum).mod(cs.orderOfBasePoint)

    MultRelationNIZKProof(X, Z, x_, y_, z_)
  }

  /**
    * @param encryptedValue An encrypted value
    * @param encryptedUnitVector an encrypted unit vector
    * @param encryptedUnitVectorWithValue an encrypted vector where each element is a corresponding unit vector element
    *                                     multiplied by value
    *
    * @return true if succeeds
    */
  def verifyNIZK(
                  cs: Cryptosystem,
                  pubKey: PubKey,
                  encryptedValue: Ciphertext,
                  encryptedUnitVector: Seq[Ciphertext],
                  encryptedUnitVectorWithValue: Seq[Ciphertext],
                  proof: MultRelationNIZKProof
                ): Boolean = {
    require(encryptedUnitVector.size == encryptedUnitVectorWithValue.size)

    val challenge = new BigInteger(
      cs.hash256 {
        pubKey.getEncoded(true) ++
        encryptedValue._1.getEncoded(true) ++
        encryptedValue._2.getEncoded(true) ++
        proof.X._1.getEncoded(true) ++
        proof.X._2.getEncoded(true) ++
        proof.Z._1.getEncoded(true) ++
        proof.Z._2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val accum = (cs.infinityPoint, cs.infinityPoint)
    var exponent = core.One
    val (vMult, uMult) = encryptedUnitVectorWithValue.zip(encryptedUnitVector).zipWithIndex.foldLeft((accum,accum)) {
      case ((vAcc,uAcc), ((v,u),i)) =>
        exponent = exponent.multiply(challenge).mod(cs.orderOfBasePoint)
        cs.add(vAcc, cs.multiply(v,exponent)) -> cs.add(uAcc, cs.multiply(u,exponent))
    }

    val Z_VMult = cs.add(proof.Z, vMult)
    val Cx = cs.multiply(encryptedValue, proof.x)
    val CxEnc = cs.add(Cx, cs.encrypt(pubKey, proof.z, core.Zero))
    val check1 = Z_VMult._1.equals(CxEnc._1) && Z_VMult._2.equals(CxEnc._2)

    val X_UMult = cs.add(proof.X, uMult)
    val Enc_xy = cs.encrypt(pubKey, proof.y, proof.x)
    val check2 = X_UMult._1.equals(Enc_xy._1) && X_UMult._2.equals(Enc_xy._2)

    check1 && check2
  }

  def produceEncryptedUnitVectorWithValue(cs: Cryptosystem,
                                          pubKey: PubKey,
                                          encryptedValue: Ciphertext,
                                          unitVector: Seq[BigInteger]
                                         ): Seq[(Ciphertext, Randomness)] = {

    require(unitVector.filter(_.equals(core.One)).size == 1)
    require(unitVector.filter(_.equals(core.Zero)).size == (unitVector.size - 1))

    unitVector.map { u =>
      val Cu = cs.multiply(encryptedValue, u)
      val t = cs.getRand
      val Enc = cs.encrypt(pubKey, t, core.Zero)
      cs.add(Cu, Enc) -> t
    }
  }
}
