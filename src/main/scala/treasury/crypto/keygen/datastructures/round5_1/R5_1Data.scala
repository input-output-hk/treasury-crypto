package treasury.crypto.keygen.datastructures.round5_1

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.{Cryptosystem, HasSize}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.keygen.IntAccumulator
import treasury.crypto.keygen.datastructures.round4.{OpenedShare, OpenedShareSerializer}

import scala.util.Try

case class R5_1Data(
                     issuerID:        Integer,
                     violatorsShares: Array[(Integer, OpenedShare)] // decrypted share from violator to issuer of this message
                   )
  extends HasSize with BytesSerializable {

  override type M = R5_1Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = R5_1DataSerializer

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

object R5_1DataSerializer extends Serializer[R5_1Data, DiscreteLogGroup] {

  override def toBytes(obj: R5_1Data): Array[Byte] = {

    val violatorsSharesBytes = obj.violatorsShares.foldLeft(Array[Byte]()){(acc, vs) => acc ++ Ints.toByteArray(vs._1) ++ Ints.toByteArray(vs._2.size) ++ vs._2.bytes}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.violatorsShares.length),
      violatorsSharesBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], csOpt: Option[DiscreteLogGroup]): Try[R5_1Data] = Try {
    val offset = IntAccumulator(0)

    val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val violatorsSharesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val violatorsShares = for (_ <- 0 until violatorsSharesLen) yield {
      val violatorID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val violatorsShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val violatorsShareBytes = bytes.slice(offset.value, offset.plus(violatorsShareBytesLen))
      (new Integer(violatorID), OpenedShareSerializer.parseBytes(violatorsShareBytes, csOpt).get)
    }

    R5_1Data(issuerID, violatorsShares.toArray)
  }
}
