package treasury.crypto.keygen.datastructures.round2

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.{Cryptosystem, HasSize}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

case class R2Data(issuerID:   Integer,
                  complaints: Array[ComplaintR2])

  extends HasSize with BytesSerializable {

  override type M = R2Data
  override val serializer: Serializer[M] = R2DataSerializer

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

object R2DataSerializer extends Serializer[R2Data] {

  override def toBytes(obj: R2Data): Array[Byte] = {

    val complaintsBytes = obj.complaints.foldLeft(Array[Byte]()){(acc, c) => acc ++ Ints.toByteArray(c.size) ++ c.bytes}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.complaints.length),
      complaintsBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[R2Data] = Try {

    val offset = IntAccumulator(0)

    val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val complaintsLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val complaints = for (_ <- 0 until complaintsLen) yield {
      val complaintBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val complaintBytes = bytes.slice(offset.value, offset.plus(complaintBytesLen))
      ComplaintR2Serializer.parseBytes(complaintBytes, cs).get
    }

    R2Data(issuerID, complaints.toArray)
  }
}

