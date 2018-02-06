package treasury.crypto.keygen.datastructures

import com.google.common.primitives.{Bytes, Ints, Shorts}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.core.{Cryptosystem, HasSize, Point, PubKey}
import treasury.crypto.nizk.{ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

import scala.util.Try

//----------------------------------------------------------
// Tally decryption data structures
//
case class C1Share(
    issuerID:           Integer,
    issuerPubKey:       PubKey,
    decryptedC1:        Seq[Point],
    decryptedC1Proofs:  Seq[ElgamalDecrNIZKProof]
) extends HasSize with BytesSerializable {

  override type M = C1Share
  override val serializer = C1ShareSerializer

  def size: Int = bytes.length
}

object C1ShareSerializer extends Serializer[C1Share] {

  override def toBytes(obj: C1Share): Array[Byte] = {
    val pubKeyBytes = obj.issuerPubKey.getEncoded(true)
    val decryptedC1Bytes = obj.decryptedC1.foldLeft(Array[Byte]()) { (acc, c1) =>
      val c1Bytes = c1.getEncoded(true)
      Bytes.concat(acc, Array(c1Bytes.length.toByte), c1Bytes)
    }
    val proofsBytes = obj.decryptedC1Proofs.foldLeft(Array[Byte]()) { (acc, proof) =>
      Bytes.concat(acc, proof.bytes)
    }
    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Array(pubKeyBytes.length.toByte), pubKeyBytes,
      Shorts.toByteArray(obj.decryptedC1.length.toShort), decryptedC1Bytes,
      Shorts.toByteArray(obj.decryptedC1Proofs.length.toShort), proofsBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[C1Share] = Try {
    val issuerID = Ints.fromByteArray(bytes.slice(0,4))

    val pubKeyLen = bytes(4)
    val pubKey = cs.decodePoint(bytes.slice(5,pubKeyLen+5))
    var pos = 5+pubKeyLen

    val decryptedC1Len = Shorts.fromByteArray(bytes.slice(pos, pos+2))
    pos = pos + 2
    val decryptedC1 = (0 until decryptedC1Len).map { _ =>
      val len = bytes(pos)
      val point = cs.decodePoint(bytes.slice(pos+1, pos+1+len))
      pos = pos + len + 1
      point
    }

    val proofsLen = Shorts.fromByteArray(bytes.slice(pos, pos+2))
    pos = pos + 2
    val decryptedC1Proofs = (0 until proofsLen).map { _ =>
      val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes.drop(pos), cs).get
      pos = pos + proof.bytes.length
      proof
    }

    C1Share(issuerID, pubKey, decryptedC1, decryptedC1Proofs)
  }
}
