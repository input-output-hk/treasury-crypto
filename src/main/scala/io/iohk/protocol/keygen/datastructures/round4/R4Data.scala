package io.iohk.protocol.keygen.datastructures.round4

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize

import scala.util.Try

case class R4Data(
                   issuerID:    Int,
                   complaints:  Array[ComplaintR4]
                 )
  extends HasSize with BytesSerializable {

  override type M = R4Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = R4DataSerializer

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

object R4DataSerializer extends Serializer[R4Data, DiscreteLogGroup] {

  override def toBytes(obj: R4Data): Array[Byte] = {

    val complaintsBytes = obj.complaints.foldLeft(Array[Byte]()){(acc, c) => acc ++ Ints.toByteArray(c.size) ++ c.bytes}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.complaints.length),
      complaintsBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], ctxOpt: Option[DiscreteLogGroup]): Try[R4Data] = Try {
    case class IntAccumulator(var value: Int = 0){
      def plus(i: Int): Int = {value += i; value}
    }

    val ctx = ctxOpt.get
    val offset = IntAccumulator(0)

    val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val complaintsLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val complaints = for (_ <- 0 until complaintsLen) yield {
      val complaintBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val complaintBytes = bytes.slice(offset.value, offset.plus(complaintBytesLen))
      ComplaintR4Serializer.parseBytes(complaintBytes, Option(ctx)).get
    }

    R4Data(issuerID, complaints.toArray)
  }
}
