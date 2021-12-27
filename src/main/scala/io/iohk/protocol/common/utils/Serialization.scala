package io.iohk.protocol.common.utils

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.Serializer

import scala.util.Try

object Serialization {

  def serializeSeq[M, D](elems: Seq[M],
                         serializer: Serializer[M, D]): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(elems.length),
      elems.foldLeft(Array[Byte]()){
        (acc, elem) =>
          val elem_bytes = serializer.toBytes(elem)
          acc ++ Ints.toByteArray(elem_bytes.length) ++ elem_bytes
      }
    )
  }

  def parseSeq[M: Manifest, D](bytes: Array[Byte],
                               serializer: Serializer[M, D])
                              (implicit group: D): Try[(Array[M], Int)] = Try{
    val elems_num = Ints.fromByteArray(bytes.slice(0, Ints.BYTES))
    Array.range(0, elems_num).foldLeft((Array[M](), Ints.BYTES)){
      case ((elem, offset), _) =>
        val elem_bytes_offset = offset + Ints.BYTES
        val elem_bytes_len = Ints.fromByteArray(bytes.slice(offset, elem_bytes_offset))
        val elem_bytes = bytes.slice(elem_bytes_offset, elem_bytes_offset + elem_bytes_len)
        (elem ++ Array(serializer.parseBytes(elem_bytes, Some(group)).get),
         elem_bytes_offset + elem_bytes_len)
    }
  }

  def serializationIsCorrect[M, D](data: Seq[M], serializer: Serializer[M, D])
                                  (implicit group: D): Boolean = {
    val dataBytes = data.map(serializer.toBytes)
    val dataParsed = dataBytes.map(serializer.parseBytes(_, Some(group)))

    dataParsed.zip(data).zip(dataBytes).forall{
      case((parsed, initial), initialBytes) =>
        parsed.isSuccess &&
        (parsed.get == initial) &&
        (serializer.toBytes(parsed.get) sameElements initialBytes)
    }
  }
}

object GroupElementSerializer extends Serializer[GroupElement, DiscreteLogGroup]{
  def toBytes(obj: GroupElement): Array[Byte] = {
    obj.bytes
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[GroupElement] = Try{
    decoder.get.reconstructGroupElement(bytes).get
  }
}

object BigIntSerializer extends Serializer[BigInt, DiscreteLogGroup]{
  def toBytes(obj: BigInt): Array[Byte] = {
    obj.toByteArray
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup] = None): Try[BigInt] = Try{
    BigInt(bytes)
  }
}
