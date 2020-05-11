package io.iohk.protocol.keygen.datastructures_new.round1

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class R1Data(
    issuerID: Int,
    E:        Vector[GroupElement],   // commitments for coefficients of both polynomials (E = g*a_i + h*b_i; i=[0; t))
    S_a:      Vector[SecretShare],    // poly_a shares for each of committee members (except the issuer)
    S_b:      Vector[SecretShare]     // poly_b shares for each of committee members (except the issuer)
  ) extends BytesSerializable {

  override type M = R1Data
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = R1DataSerializer

//  def size: Int = bytes.length
//
//  def canEqual(a: Any): Boolean = a.isInstanceOf[M]
//
//  override def equals(that: Any): Boolean =
//    that match {
//      case that: M => that.canEqual(this) && this.hashCode == that.hashCode
//      case _ => false
//    }
//
//  override def hashCode: Int = {
//
//    import java.util.zip.CRC32
//
//    val checksum = new CRC32
//    checksum.update(bytes, 0, bytes.length)
//    checksum.getValue.toInt
//  }
}

object R1DataSerializer extends Serializer[R1Data, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: R1Data): Array[Byte] = {

    val E_bytes   = obj.E.foldLeft(Array[Byte]()) { (acc, e) =>
      val bytes = e.bytes
      acc ++ Ints.toByteArray(bytes.length) ++ bytes
    }
    val S_a_bytes = obj.S_a.foldLeft(Array[Byte]()) { (acc, s) =>
      val bytes = s.bytes
      acc ++ Ints.toByteArray(bytes.size) ++ bytes
    }
    val S_b_bytes = obj.S_b.foldLeft(Array[Byte]()) { (acc, s) =>
      val bytes = s.bytes
      acc ++ Ints.toByteArray(bytes.size) ++ bytes
    }

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.E.length),
      E_bytes,
      Ints.toByteArray(obj.S_a.length),
      S_a_bytes,
      Ints.toByteArray(obj.S_b.length),
      S_b_bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[(DiscreteLogGroup, BlockCipher)]): Try[R1Data] = Try {
    case class IntAccumulator(var value: Int = 0){
      def plus(i: Int): Int = {value += i; value}
    }

    val group = decoder.get._1
    val offset = IntAccumulator(0)

    val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val E_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val E = for (_ <- 0 until E_len) yield {
      val e_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val e_bytes = bytes.slice(offset.value, offset.plus(e_len))
      group.reconstructGroupElement(e_bytes).get
    }

    val S_a_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val S_a = for (_ <- 0 until S_a_len) yield {
        val S_a_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
        val S_a_bytes = bytes.slice(offset.value, offset.plus(S_a_bytes_len))
        SecretShareSerializer.parseBytes(S_a_bytes, decoder).get
    }

    val S_b_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val S_b = for (_ <- 0 until S_b_len) yield {
        val S_b_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
        val S_b_bytes = bytes.slice(offset.value, offset.plus(S_b_bytes_len))
        SecretShareSerializer.parseBytes(S_b_bytes, decoder).get
    }

    R1Data(issuerID, E.toVector, S_a.toVector, S_b.toVector)
  }
}