package treasury.crypto.nizk.shvzk_new

import com.google.common.primitives.{Bytes, Shorts}
import treasury.crypto.core.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

case class SHVZKProof(
                       IBA: Seq[(GroupElement, GroupElement, GroupElement)],
                       Dk: Seq[ElGamalCiphertext],
                       zwv: Seq[(BigInt, BigInt, BigInt)],
                       R: BigInt
) extends BytesSerializable {

  override type M = SHVZKProof
  override type DECODER = DiscreteLogGroup
  override val serializer = SHVZKProofSerializer

  def size: Int = bytes.length
}

object SHVZKProofSerializer extends Serializer[SHVZKProof, DiscreteLogGroup] {

  override def toBytes(p: SHVZKProof): Array[Byte] = {

    val IBAbytes = p.IBA.foldLeft(Array[Byte]()) { (acc, b) =>
      val I = b._1.bytes
      val B = b._2.bytes
      val A = b._3.bytes
      Bytes.concat(acc, Array(I.length.toByte), I, Array(B.length.toByte), B, Array(A.length.toByte), A)
    }
    val DkBytes = p.Dk.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
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

  override def parseBytes(bytes: Array[Byte], groupOpt: Option[DiscreteLogGroup]): Try[SHVZKProof] = Try {
    val group = groupOpt.get
    val IBALength = Shorts.fromByteArray(bytes.slice(0, 2))
    var position = 2

    val IBA: Seq[(GroupElement, GroupElement, GroupElement)] = (0 until IBALength*3).map { _ =>
      val len = bytes(position)
      val groupElement = group.reconstructGroupElement(bytes.slice(position+1, position+1+len)).get
      position = position + len + 1
      groupElement
    }.toArray.grouped(3).map(x => (x(0), x(1), x(2))).toSeq

    val DkLength = Shorts.fromByteArray(bytes.slice(position, position+2))
    position = position + 2
    val Dk: Seq[ElGamalCiphertext] = (0 until DkLength).map { _ =>
      val len = bytes(position)
      val ciphertext = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), groupOpt).get
      position = position + len + 1
      ciphertext
    }

    val zwvLength = Shorts.fromByteArray(bytes.slice(position, position+2))
    position = position + 2
    val zwv: Seq[(BigInt, BigInt, BigInt)] = (0 until zwvLength*3).map { _ =>
      val len = bytes(position)
      val elem = BigInt(bytes.slice(position+1, position+1+len))
      position = position + len + 1
      elem
    }.toArray.grouped(3).map(x => (x(0), x(1), x(2))).toSeq

    val RLength = bytes(position)
    val R = BigInt(bytes.slice(position+1, position+1+RLength))

    SHVZKProof(IBA, Dk, zwv, R)
  }
}