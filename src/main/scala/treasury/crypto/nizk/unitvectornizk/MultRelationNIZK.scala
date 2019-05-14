package treasury.crypto.nizk.unitvectornizk

import java.math.BigInteger

import com.google.common.primitives.Bytes
import treasury.crypto.core.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer, LiftedElGamalEnc}
import treasury.crypto.core.encryption.encryption.{PubKey, Randomness}
import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import treasury.crypto.core.primitives.hash.CryptographicHash
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.nizk.unitvectornizk.MultRelationNIZK.MultRelationNIZKProof

import scala.util.Try

/* MultRelationNIZK implements non-interactive zero knowledge protocol to prove a multiplicative relation between
 * two encrypted vectors.
 * Given an encrypted unit vector U and an encrypted value C, the protocol allows to prove that another encrypted
 * vector V contains elements from U multiplied by the value encrypted in C.
 */

object MultRelationNIZK {

  case class MultRelationNIZKProof(X: ElGamalCiphertext, Z: ElGamalCiphertext, x: BigInt, y: BigInt, z: BigInt) extends BytesSerializable {

    override type M = MultRelationNIZKProof
    override type DECODER = DiscreteLogGroup
    override val serializer = MultRelationNIZKProofSerializer

    lazy val size: Int = bytes.length
  }

  /**
    * @param encryptedValue An encrypted value
    * @param unitVector (witness) a plain unit vector
    * @param unitVectorRandomness (witness) an array of random values that were used to encrypt unit vector
    * @param zeroVectorRandomness (witness) an array of random values that were used to encrypt zero vector (which is
    *                             needed to produce V)
    * @return MultRelationNIZKProof
    */
  def produceNIZK(pubKey: PubKey, encryptedValue: ElGamalCiphertext, unitVector: Seq[BigInt],
                  unitVectorRandomness: Seq[Randomness], zeroVectorRandomness: Seq[Randomness])
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[MultRelationNIZKProof] = Try {
    require(unitVector.size == unitVectorRandomness.size)
    require(unitVector.size == zeroVectorRandomness.size)
    require(unitVector.count(_ == 1) == 1)
    require(unitVector.count(_ == 0) == (unitVector.size - 1))

    val x = dlogGroup.createRandomNumber
    val y = dlogGroup.createRandomNumber
    val z = dlogGroup.createRandomNumber

    val X = LiftedElGamalEnc.encrypt(pubKey, y, x).get
    val Z = encryptedValue.pow(x).get * LiftedElGamalEnc.encrypt(pubKey, z, 0).get

    val challenge = new BigInteger(
      hashFunction.hash {
        pubKey.bytes ++
        encryptedValue.bytes ++
        X.bytes ++
        Z.bytes
      }).mod(dlogGroup.groupOrder)

    val uvIndex = unitVector.indexOf(1)
    val x_ = (x + challenge.pow(uvIndex+1)) mod(dlogGroup.groupOrder)

    val rSum = unitVectorRandomness.zipWithIndex.foldLeft(BigInt(0)) { case (acc, (r,i)) =>
      acc + (r * challenge.pow(i+1))
    }
    val y_ = (y + rSum) mod(dlogGroup.groupOrder)

    val tSum = zeroVectorRandomness.zipWithIndex.foldLeft(BigInt(0)) { case (acc, (t,i)) =>
      acc + (t * challenge.pow(i+1))
    }
    val z_ = (z + tSum) mod(dlogGroup.groupOrder)

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
  def verifyNIZK(pubKey: PubKey, encryptedValue: ElGamalCiphertext, encryptedUnitVector: Seq[ElGamalCiphertext],
                 encryptedUnitVectorWithValue: Seq[ElGamalCiphertext], proof: MultRelationNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {
    require(encryptedUnitVector.size == encryptedUnitVectorWithValue.size)

    val challenge = new BigInteger(
      hashFunction.hash {
        pubKey.bytes ++
        encryptedValue.bytes ++
        proof.X.bytes ++
        proof.Z.bytes
      }).mod(dlogGroup.groupOrder)

    val accum = ElGamalCiphertext(dlogGroup.groupIdentity, dlogGroup.groupIdentity)
    var exponent = BigInt(1)
    val (vMult, uMult) = encryptedUnitVectorWithValue.zip(encryptedUnitVector).zipWithIndex.foldLeft((accum,accum)) {
      case ((vAcc,uAcc), ((v,u),i)) =>
        exponent = (exponent * challenge) mod(dlogGroup.groupOrder)
        vAcc * v.pow(exponent).get -> uAcc * u.pow(exponent).get
    }

    val Z_VMult = proof.Z * vMult
    val Cx = encryptedValue.pow(proof.x).get
    val CxEnc = Cx * LiftedElGamalEnc.encrypt(pubKey, proof.z, 0).get
    val check1 = Z_VMult.c1.equals(CxEnc.c1) && Z_VMult.c2.equals(CxEnc.c2)

    val X_UMult = proof.X * uMult
    val Enc_xy = LiftedElGamalEnc.encrypt(pubKey, proof.y, proof.x).get
    val check2 = X_UMult.c1.equals(Enc_xy.c1) && X_UMult.c2.equals(Enc_xy.c2)

    check1 && check2
  }.getOrElse(false)

  def produceEncryptedUnitVectorWithValue(pubKey: PubKey, encryptedValue: ElGamalCiphertext, unitVector: Seq[BigInt])
                                         (implicit dlogGroup: DiscreteLogGroup): Seq[(ElGamalCiphertext, Randomness)] = {

    require(unitVector.count(_.equals(1)) == 1)
    require(unitVector.count(_.equals(0)) == (unitVector.size - 1))

    unitVector.map { u =>
      val Cu = encryptedValue.pow(u).get
      val t = dlogGroup.createRandomNumber
      val Enc = LiftedElGamalEnc.encrypt(pubKey, t, 0).get
      Cu * Enc -> t
    }
  }
}

object MultRelationNIZKProofSerializer extends Serializer[MultRelationNIZKProof, DiscreteLogGroup] {

  override def toBytes(p: MultRelationNIZKProof): Array[Byte] = {
    val Xbytes = p.X.bytes
    val Zbytes = p.Z.bytes
    assert(Xbytes.length < Byte.MaxValue)
    assert(Zbytes.length < Byte.MaxValue)
    val XZbytes = Bytes.concat(Array(Xbytes.length.toByte), Xbytes, Array(Zbytes.length.toByte), Zbytes)

    val xbytes = p.x.toByteArray
    val ybytes = p.y.toByteArray
    val zbytes = p.z.toByteArray
    val xyzbytes = Bytes.concat(
      Array(xbytes.length.toByte), xbytes,
      Array(ybytes.length.toByte), ybytes,
      Array(zbytes.length.toByte), zbytes)

    Bytes.concat(XZbytes, xyzbytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[MultRelationNIZKProof] = Try {
    var position = 0
    def nextPosition= position + 1 + bytes(position)

    val X = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, nextPosition), decoder).get
    position = nextPosition

    val Z = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, nextPosition), decoder).get
    position = nextPosition

    val x = BigInt(bytes.slice(position+1, nextPosition))
    position = nextPosition

    val y = BigInt(bytes.slice(position+1, nextPosition))
    position = nextPosition

    val z = BigInt(bytes.slice(position+1, nextPosition))

    MultRelationNIZKProof(X, Z, x, y, z)
  }
}