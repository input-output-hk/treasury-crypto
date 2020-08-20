package io.iohk.protocol.keygen.datastructures.round5_1

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.keygen.datastructures.round4.{OpenedShare, OpenedShareSerializer}
import io.iohk.protocol.voting.common.Issuer

import scala.util.Try

class ViolatorsSharesData(val issuerID:        Int,
                          val violatorsShares: Seq[(Int, OpenedShare)] // decrypted share from violator to issuer of this message
                         )
  extends HasSize with BytesSerializable with Issuer {

  override type M = ViolatorsSharesData
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ViolatorsSharesDataSerializer

  override val issuerId: Int = issuerID

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

object ViolatorsSharesDataSerializer extends Serializer[ViolatorsSharesData, DiscreteLogGroup] {

  override def toBytes(obj: ViolatorsSharesData): Array[Byte] = {

    val violatorsSharesBytes = obj.violatorsShares.foldLeft(Array[Byte]()){(acc, vs) => acc ++ Ints.toByteArray(vs._1) ++ Ints.toByteArray(vs._2.size) ++ vs._2.bytes}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.violatorsShares.length),
      violatorsSharesBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], ctxOpt: Option[DiscreteLogGroup]): Try[ViolatorsSharesData] = Try {
    case class IntAccumulator(var value: Int = 0){
      def plus(i: Int): Int = {value += i; value}
    }

    val offset = IntAccumulator(0)

    val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val violatorsSharesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val violatorsShares = for (_ <- 0 until violatorsSharesLen) yield {
      val violatorID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val violatorsShareBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val violatorsShareBytes = bytes.slice(offset.value, offset.plus(violatorsShareBytesLen))
      (violatorID, OpenedShareSerializer.parseBytes(violatorsShareBytes, ctxOpt).get)
    }

    new ViolatorsSharesData(issuerID, violatorsShares)
  }
}

