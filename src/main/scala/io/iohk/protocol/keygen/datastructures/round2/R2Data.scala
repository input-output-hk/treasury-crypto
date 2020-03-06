package io.iohk.protocol.keygen.datastructures.round2

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize

import scala.util.Try

case class R2Data(issuerID:   Int,
                  complaints: Array[ComplaintR2])

  extends HasSize with BytesSerializable {

  override type M = R2Data
  override type DECODER = (DiscreteLogGroup, BlockCipher)
  override val serializer: Serializer[M, DECODER] = R2DataSerializer

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

object R2DataSerializer extends Serializer[R2Data, (DiscreteLogGroup, BlockCipher)] {

  override def toBytes(obj: R2Data): Array[Byte] = {

    val complaintsBytes = obj.complaints.foldLeft(Array[Byte]()){(acc, c) => acc ++ Ints.toByteArray(c.size) ++ c.bytes}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.complaints.length),
      complaintsBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], ctxOpt: Option[(DiscreteLogGroup, BlockCipher)]): Try[R2Data] = Try {
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
      ComplaintR2Serializer.parseBytes(complaintBytes, Option(ctx)).get
    }

    R2Data(issuerID, complaints.toArray)
  }
}

