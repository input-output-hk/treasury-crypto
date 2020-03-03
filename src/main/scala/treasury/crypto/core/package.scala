package treasury.crypto

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints}
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG
import org.bouncycastle.math.ec.ECPoint
import org.scalameter._
import treasury.crypto.core.encryption.elgamal.ElGamalCiphertext
import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

package object core {

  type PrivKey = core.encryption.encryption.PrivKey
  type PubKey = core.encryption.encryption.PubKey
  type KeyPair = (PrivKey, PubKey)
  type Ciphertext = ElGamalCiphertext
  type Randomness = core.encryption.encryption.Randomness
  type Point = GroupElement
  type Element = BigInt

  trait HasSize {
    def size: Int
  }

  val Zero: BigInteger = BigInteger.ZERO
  val One:  BigInteger = BigInteger.ONE

  // Generates deterministic sequence of elements in Zp field (p = orderOfBasePoint), which depends on seed
//  case class DRNG (seed: Array[Byte], cs: Cryptosystem) {
//
//    private val drng = new HashSP800DRBG(new SHA256Digest(), 256, new SingleEntropySourceProvider(cs.hash256(seed)).get(256), null, null)
//    private val randBytes = new Array[Byte]((cs.orderOfBasePoint.bitLength.toFloat / 8).ceil.toInt)
//
//    def getRand: Randomness = {
//      drng.generate(randBytes, null, false)
//      BigInt(randBytes).mod(cs.orderOfBasePoint)
//    }
//  }

//  case class HybridCiphertext(encryptedKey: Ciphertext, encryptedMessage: Array[Byte])
//    extends BytesSerializable {
//
//    override type M = HybridCiphertext
//    override type DECODER = Cryptosystem
//    override val serializer: Serializer[M, DECODER] = HybridCiphertextSerializer
//
//    def size: Int = bytes.length
//  }
//
//  object HybridCiphertextSerializer extends Serializer[HybridCiphertext, Cryptosystem] {
//
//    override def toBytes(obj: HybridCiphertext): Array[Byte] = {
//      Bytes.concat(
//        CiphertextSerizlizer.toBytes(obj.encryptedKey),
//        Ints.toByteArray(obj.encryptedMessage.length),
//        obj.encryptedMessage
//      )
//    }
//
//    override def parseBytes(bytes: Array[Byte], csOpt: Option[Cryptosystem]): Try[HybridCiphertext] = Try {
//      val cs = csOpt.get
//      val offset = IntAccumulator(0)
//
//      val encryptedKey = CiphertextSerizlizer.parseBytes(bytes, Option(cs)).get
//      offset.plus(CiphertextSerizlizer.toBytes(encryptedKey).length)
//
//      val encryptedMessageLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
//      val encryptedMessage = bytes.slice(offset.value, offset.plus(encryptedMessageLen))
//
//      HybridCiphertext(encryptedKey, encryptedMessage)
//    }
//  }
//
  case class HybridPlaintext(decryptedKey: GroupElement, decryptedMessage: Array[Byte])
    extends BytesSerializable {

    override type M = HybridPlaintext
    override type DECODER = DiscreteLogGroup
    override val serializer: Serializer[M, DECODER] = HybridPlaintextSerializer

    def size: Int = bytes.length
  }

  object HybridPlaintextSerializer extends Serializer[HybridPlaintext, DiscreteLogGroup] {

    override def toBytes(obj: HybridPlaintext): Array[Byte] =
    {
      val decryptedKeyBytes = obj.decryptedKey.bytes

      Bytes.concat(
        Ints.toByteArray(decryptedKeyBytes.length),
        decryptedKeyBytes,
        Ints.toByteArray(obj.decryptedMessage.length),
        obj.decryptedMessage
      )
    }

    override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[HybridPlaintext] = Try {
      val group = decoder.get

      val decryptedKeyBytesLen = Ints.fromByteArray(bytes.slice(0, 4))
      val decryptedKeyBytes = bytes.slice(4, 4 + decryptedKeyBytesLen)

      val decryptedMessageLen = Ints.fromByteArray(bytes.slice(4 + decryptedKeyBytesLen, 8 + decryptedKeyBytesLen))
      val decryptedMessage = bytes.slice(8 + decryptedKeyBytesLen, 8 + decryptedKeyBytesLen + decryptedMessageLen)

      HybridPlaintext(
        group.reconstructGroupElement(decryptedKeyBytes).get,
        decryptedMessage
      )
    }
  }
//
//  object CiphertextSerizlizer extends Serializer[Ciphertext, Cryptosystem] {
//
//    override def toBytes(obj: Ciphertext): Array[Byte] = {
//      val c1Bytes = obj._1.getEncoded(true)
//      val c2Bytes = obj._2.getEncoded(true)
//
//      Bytes.concat(
//        Ints.toByteArray(c1Bytes.length),
//        c1Bytes,
//        Ints.toByteArray(c2Bytes.length),
//        c2Bytes
//      )
//    }
//
//    override def parseBytes(bytes: Array[Byte], csOpt: Option[Cryptosystem]): Try[Ciphertext] = Try {
//      val cs = csOpt.get
//      val offset = IntAccumulator(0)
//
//      val c1BytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
//      val c1Bytes = bytes.slice(offset.value, offset.plus(c1BytesLen))
//
//      val c2BytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
//      val c2Bytes = bytes.slice(offset.value, offset.plus(c2BytesLen))
//
//      (cs.decodePoint(c1Bytes), cs.decodePoint(c2Bytes))
//    }
//  }
//
//  object PointSerizlizer extends Serializer[Point, Cryptosystem] {
//
//    override def toBytes(obj: Point): Array[Byte] = {
//      val bytes = obj.getEncoded(true)
//      Bytes.concat(Ints.toByteArray(bytes.length), bytes)
//    }
//
//    override def parseBytes(bytes: Array[Byte], csOpt: Option[Cryptosystem]): Try[Point] = Try {
//      val cs = csOpt.get
//      val bytesLen = Ints.fromByteArray(bytes.slice(0, 4))
//      val pointBytes = bytes.slice(4, 4 + bytesLen)
//      cs.decodePoint(pointBytes)
//    }
//  }

  object VoteCases extends Enumeration {
    val Yes, No, Abstain = Value
  }

  object TimeUtils {
    def time[R](block: => R): R = {
      val t0 = System.nanoTime()
      val result = block
      val t1 = System.nanoTime()
      println("Elapsed time: " + (t1-t0)/1000000000 + " sec")
      result
    }

    def time[R](msg: String, block: => R): R = {
      val t0 = System.nanoTime()
      val result = block
      val t1 = System.nanoTime()
      println(msg + " " + (t1-t0)/1000000000 + " sec")
      result
    }

    def time_ms[R](msg: String, block: => R): R = {
      val t0 = System.nanoTime()
      val result = block
      val t1 = System.nanoTime()
      println(msg + " " + (t1-t0)/1000000 + " ms")
      result
    }

    def get_time_average_s[R](msg: String, block: => R, n: Int): (R, Float) = {
      val t0 = System.nanoTime()
      val result = block
      val t1 = System.nanoTime()
      val time = ((t1-t0).toFloat/1000000000)/n
      print(msg + "\t" + time + " s;\t")
      (result, time)
    }

    def accurate_time[R](msg: String, block: => R): Unit = {
      val time = config(
        Key.exec.benchRuns -> 20,
      ) withWarmer {
        new Warmer.Default
      } withMeasurer {
        new Measurer.IgnoringGC
      } measure {
        block
      }
      println(msg + " " + time.value.toInt  + " ms")
    }
  }

  object SizeUtils {
    def getSize[T <: HasSize](vector: Seq[T]): Int = {
      val maxSize = vector.maxBy(_.size).size
      val totalSize = vector.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

      println(maxSize + " B;\t" + totalSize + " B")

      totalSize
    }
  }
}
