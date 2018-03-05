package treasury.crypto.nizk

import java.math.BigInteger

import com.google.common.primitives.Bytes
import treasury.crypto.core._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

object ElgamalDecrNIZK {

  def produceNIZK(
    cs: Cryptosystem,
    ciphertext: Ciphertext,
    privKey: PrivKey
  ): ElgamalDecrNIZKProof = {

    val drng = DRNG(privKey.toByteArray ++ ciphertext._1.getEncoded(true) ++ ciphertext._2.getEncoded(true), cs)
    val w = drng.getRand
    val A1 = cs.basePoint.multiply(w)
    val A2 = ciphertext._1.multiply(w)
    val D = ciphertext._1.multiply(privKey)

    val e = new BigInteger(
      cs.hash256 {
        ciphertext._1.getEncoded(true) ++
        ciphertext._2.getEncoded(true) ++
        D.getEncoded(true) ++
        A1.getEncoded(true) ++
        A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val z = privKey.multiply(e).add(w).mod(cs.orderOfBasePoint)

    ElgamalDecrNIZKProof(A1.normalize(), A2.normalize(), z)
  }

  def verifyNIZK(
    cs: Cryptosystem,
    pubKey: PubKey,
    ciphertext: Ciphertext,
    plaintext: Point,
    proof: ElgamalDecrNIZKProof
  ): Boolean = {

    val D = ciphertext._2.subtract(plaintext)
    val e = new BigInteger(
      cs.hash256 {
        ciphertext._1.getEncoded(true) ++
          ciphertext._2.getEncoded(true) ++
          D.getEncoded(true) ++
          proof.A1.getEncoded(true) ++
          proof.A2.getEncoded(true)
      }).mod(cs.orderOfBasePoint)

    val gz = cs.basePoint.multiply(proof.z)
    val heA1 = pubKey.multiply(e).add(proof.A1)

    val C1z = ciphertext._1.multiply(proof.z)
    val DeA2 = D.multiply(e).add(proof.A2)

    gz.equals(heA1) && C1z.equals(DeA2)
  }
}

case class ElgamalDecrNIZKProof(A1: Point, A2: Point, z: Element) extends BytesSerializable {

  override type M = ElgamalDecrNIZKProof
  override val serializer = ElgamalDecrNIZKProofSerializer

  def size: Int = bytes.length
}

object ElgamalDecrNIZKProofSerializer extends Serializer[ElgamalDecrNIZKProof] {

  override def toBytes(obj: ElgamalDecrNIZKProof): Array[Byte] = {
    val A1Bytes = obj.A1.getEncoded(true)
    val A2Bytes = obj.A2.getEncoded(true)
    val zBytes = obj.z.toByteArray

    Bytes.concat(Array(A1Bytes.length.toByte), A1Bytes,
      Array(A2Bytes.length.toByte), A2Bytes,
      Array(zBytes.length.toByte), zBytes)
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[ElgamalDecrNIZKProof] = Try {
    val A1Len = bytes(0)
    val A1 = cs.decodePoint(bytes.slice(1,A1Len+1))
    var pos = A1Len + 1

    val A2Len = bytes(pos)
    val A2 = cs.decodePoint(bytes.slice(pos+1,A2Len+pos+1))
    pos = pos + A2Len + 1

    val zLen = bytes(pos)
    val z = new BigInteger(bytes.slice(pos+1, pos+1+zLen))

    ElgamalDecrNIZKProof(A1, A2, z)
  }
}
