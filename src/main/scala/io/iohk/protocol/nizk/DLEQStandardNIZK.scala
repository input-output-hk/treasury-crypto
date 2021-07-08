package io.iohk.protocol.nizk

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

/**
  * The standard Discrete Log Equality NIZK which proves the relation among 4 group elements:
  *   NIZK{(H1, H2, G1, G2), (x): H1 = G1^x AND H2 = G2^x}
  */
object DLEQStandardNIZK {

  def produceNIZK(H1: GroupElement, H2: GroupElement,
                  G1: GroupElement, G2: GroupElement,
                  witness: BigInt, randomness: Option[BigInt] = None)
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[DLEQStandardNIZKProof] = Try {

    val w = randomness.getOrElse(dlogGroup.createRandomNumber)
    val A1 = G1.pow(w).get
    val A2 = G2.pow(w).get

    val e = BigInt(
      hashFunction.hash {
        H1.bytes ++
        H2.bytes ++
        G1.bytes ++
        G2.bytes ++
        A1.bytes ++
        A2.bytes
      }).mod(dlogGroup.groupOrder)

    val z = (witness * e + w) mod dlogGroup.groupOrder

    DLEQStandardNIZKProof(A1, A2, z)
  }

  def verifyNIZK(H1: GroupElement, H2: GroupElement,
                 G1: GroupElement, G2: GroupElement,
                 proof: DLEQStandardNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {

    val e = BigInt(
      hashFunction.hash {
        H1.bytes ++
          H2.bytes ++
          G1.bytes ++
          G2.bytes ++
          proof.A1.bytes ++
          proof.A2.bytes
      }).mod(dlogGroup.groupOrder)

    val G1z = G1.pow(proof.z).get
    val H1eA1 = H1.pow(e).get.multiply(proof.A1).get

    val G2z = G2.pow(proof.z).get
    val H2eA2 = H2.pow(e).get.multiply(proof.A2).get

    G1z.equals(H1eA1) && G2z.equals(H2eA2)
  }.getOrElse(false)
}

case class DLEQStandardNIZKProof(A1: GroupElement, A2: GroupElement, z: BigInt) extends BytesSerializable {

  override type M = DLEQStandardNIZKProof
  override type DECODER = DiscreteLogGroup
  override val serializer = DLEQStandardNIZKProofSerializer

  def size: Int = bytes.length
}

object DLEQStandardNIZKProofSerializer extends Serializer[DLEQStandardNIZKProof, DiscreteLogGroup] {

  override def toBytes(obj: DLEQStandardNIZKProof): Array[Byte] = {
    val A1Bytes = obj.A1.bytes
    val A2Bytes = obj.A2.bytes
    val zBytes = obj.z.toByteArray

    Bytes.concat(Array(A1Bytes.length.toByte), A1Bytes,
      Array(A2Bytes.length.toByte), A2Bytes,
      Array(zBytes.length.toByte), zBytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[DLEQStandardNIZKProof] = Try {
    val group = decoder.get
    val A1Len = bytes(0)
    val A1 = group.reconstructGroupElement(bytes.slice(1,A1Len+1)).get
    var pos = A1Len + 1

    val A2Len = bytes(pos)
    val A2 = group.reconstructGroupElement(bytes.slice(pos+1,A2Len+pos+1)).get
    pos = pos + A2Len + 1

    val zLen = bytes(pos)
    val z = BigInt(bytes.slice(pos+1, pos+1+zLen))

    DLEQStandardNIZKProof(A1, A2, z)
  }
}
