package io.iohk.core.crypto.encryption.elgamal

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

/*
 * Represents a ciphertext for the ElGamal assymetric cryptosystem.
 * It also supports a couple of methods that facilitate homomorphic transformations of a ciphertext
 */
case class ElGamalCiphertext(c1: GroupElement, c2: GroupElement) extends BytesSerializable {

  override type M = ElGamalCiphertext
  override type DECODER = DiscreteLogGroup

  override def serializer = ElGamalCiphertextSerializer

  def pow(exp: BigInt)(implicit dlog: DiscreteLogGroup): Try[ElGamalCiphertext] = Try {
    ElGamalCiphertext(c1.pow(exp).get, c2.pow(exp).get)
  }

  def multiply(that: ElGamalCiphertext)(implicit dlog: DiscreteLogGroup): Try[ElGamalCiphertext] = Try {
    ElGamalCiphertext(c1.multiply(that.c1).get, c2.multiply(that.c2).get)
  }

  @throws[Exception]("if underlying multiply failed")
  def * (that: ElGamalCiphertext)(implicit dlog: DiscreteLogGroup): ElGamalCiphertext = this.multiply(that).get
}

object ElGamalCiphertextSerializer extends Serializer[ElGamalCiphertext, DiscreteLogGroup] {

  override def toBytes(obj: ElGamalCiphertext): Array[Byte] = {
    val c1Bytes = obj.c1.bytes
    val c2Bytes = obj.c2.bytes

    Bytes.concat(Array(c1Bytes.length.toByte), c1Bytes, Array(c2Bytes.length.toByte), c2Bytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[ElGamalCiphertext] = Try {
    val c1Len = bytes(0)
    val c1Bytes = bytes.slice(1, c1Len + 1)
    val c2Len = bytes(c1Len + 1)
    val c2Bytes = bytes.slice(c1Len + 2, c1Len + 2 + c2Len)

    val group = decoder.get
    val c1 = group.reconstructGroupElement(c1Bytes).get
    val c2 = group.reconstructGroupElement(c2Bytes).get

    ElGamalCiphertext(c1, c2)
  }
}