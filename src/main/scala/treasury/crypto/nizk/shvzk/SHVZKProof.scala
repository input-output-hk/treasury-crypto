package treasury.crypto.nizk.shvzk

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints, Shorts}
import org.scalameter.Events.Failure
import treasury.crypto.core._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class SHVZKProof(
  IBA: Seq[(Point, Point, Point)],
  Dk: Seq[Ciphertext],
  zwv: Seq[(Element, Element, Element)],
  R: Element
) extends BytesSerializable {

  override type M = SHVZKProof
  override type DECODER = Cryptosystem
  override val serializer = SHVZKProofSerializer

  def size: Int = bytes.length
}

object SHVZKProofSerializer extends Serializer[SHVZKProof, Cryptosystem] {

  override def toBytes(p: SHVZKProof): Array[Byte] = {
    val IBAbytes = p.IBA.foldLeft(Array[Byte]()) { (acc, b) =>
      val I = b._1.getEncoded(true)
      val B = b._2.getEncoded(true)
      val A = b._3.getEncoded(true)
      Bytes.concat(acc, Array(I.length.toByte), I, Array(B.length.toByte), B, Array(A.length.toByte), A)
    }
    val DkBytes = p.Dk.foldLeft(Array[Byte]()) { (acc, b) =>
      val c1 = b._1.getEncoded(true)
      val c2 = b._2.getEncoded(true)
      Bytes.concat(acc, Array(c1.length.toByte), c1, Array(c2.length.toByte), c2)
    }
    val zwvBytes = p.zwv.foldLeft(Array[Byte]()) { (acc, b) =>
      val z = b._1.toByteArray
      val w = b._2.toByteArray
      val v = b._3.toByteArray
      Bytes.concat(acc, Array(z.length.toByte), z, Array(w.length.toByte), w, Array(v.length.toByte), v)
    }
    val Rbytes = p.R.toByteArray

    Bytes.concat(
      Shorts.toByteArray(p.IBA.length.toShort), IBAbytes,
      Shorts.toByteArray(p.Dk.length.toShort), DkBytes,
      Shorts.toByteArray(p.zwv.length.toShort), zwvBytes,
      Array(Rbytes.length.toByte), Rbytes)
  }

  override def parseBytes(bytes: Array[Byte], csOpt: Option[Cryptosystem]): Try[SHVZKProof] = Try {
    val cs = csOpt.get
    val IBALength = Shorts.fromByteArray(bytes.slice(0, 2))
    var position = 2
    val IBA: Seq[(Point, Point, Point)] = (0 until IBALength*3).map { _ =>
      val len = bytes(position)
      val point = cs.decodePoint(bytes.slice(position+1, position+1+len))
      position = position + len + 1
      point
    }.toArray.grouped(3).map(x => (x(0), x(1), x(2))).toSeq

    val DkLength = Shorts.fromByteArray(bytes.slice(position, position+2))
    position = position + 2
    val Dk: Seq[Ciphertext] = (0 until DkLength).map { _ =>
      val c1Len = bytes(position)
      val c1 = cs.decodePoint(bytes.slice(position+1, position+1+c1Len))
      position = position + c1Len + 1
      val c2Len = bytes(position)
      val c2 = cs.decodePoint(bytes.slice(position+1, position+1+c2Len))
      position = position + c2Len + 1
      (c1, c2)
    }

    val zwvLength = Shorts.fromByteArray(bytes.slice(position, position+2))
    position = position + 2
    val zwv: Seq[(Element, Element, Element)] = (0 until zwvLength*3).map { _ =>
      val len = bytes(position)
      val elem = new BigInteger(bytes.slice(position+1, position+1+len))
      position = position + len + 1
      elem
    }.toArray.grouped(3).map(x => (x(0), x(1), x(2))).toSeq

    val RLength = bytes(position)
    val R = new BigInteger(bytes.slice(position+1, position+1+RLength))

    SHVZKProof(IBA, Dk, zwv, R)
  }
}