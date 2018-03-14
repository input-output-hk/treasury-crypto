package treasury.crypto.keygen.datastructures.round3

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.{Cryptosystem, HasSize}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

case class R3Data(
                   issuerID:    Integer,
                   commitments: Array[Array[Byte]]
                 )
  extends HasSize with BytesSerializable {

  override type M = R3Data
  override val serializer: Serializer[M] = R3DataSerializer

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

object R3DataSerializer extends Serializer[R3Data] {

  override def toBytes(obj: R3Data): Array[Byte] = {

    val commitmentsBytes = obj.commitments.foldLeft(Array[Byte]()){(acc, c) => acc ++ Ints.toByteArray(c.length) ++ c}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.commitments.length),
      commitmentsBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[R3Data] = Try {

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