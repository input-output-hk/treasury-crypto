package io.iohk.protocol.keygen.datastructures.round3

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.HasSize
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.Cryptosystem

import scala.util.Try

case class R3Data(
                   issuerID:    Integer,
                   commitments: Array[Array[Byte]]
                 )
  extends HasSize with BytesSerializable {

  override type M = R3Data
  override type DECODER = Cryptosystem
  override val serializer: Serializer[M, DECODER] = R3DataSerializer

  def size: Int = bytes.length
  def canEqual(a: Any): Boolean = a.isInstanceOf[M]

  override def equals(that: Any): Boolean =
    that match {
      case that: M => that.canEqual(this) && this.hashCode == that.hashCode
      case _ => false
    }

  override def hashCode: Int = {

    import java.util.zip.CRC32

    val checksum = new CRC32
    checksum.update(bytes, 0, bytes.length)
    checksum.getValue.toInt
  }
}

object R3DataSerializer extends Serializer[R3Data, Cryptosystem] {

  override def toBytes(obj: R3Data): Array[Byte] = {

    val commitmentsBytes = obj.commitments.foldLeft(Array[Byte]()){(acc, c) => acc ++ Ints.toByteArray(c.length) ++ c}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.commitments.length),
      commitmentsBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], csOpt: Option[Cryptosystem]): Try[R3Data] = Try {
    case class IntAccumulator(var value: Int = 0){
      def plus(i: Int): Int = {value += i; value}
    }

    val offset = IntAccumulator(0)

    val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val commitmentsLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val commitments = for (_ <- 0 until commitmentsLen) yield {
      val commitmentsBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      bytes.slice(offset.value, offset.plus(commitmentsBytesLen))
    }

    R3Data(issuerID, commitments.toArray)
  }
}
