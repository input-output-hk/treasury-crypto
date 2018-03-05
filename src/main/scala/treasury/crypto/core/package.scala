package treasury.crypto

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints}
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG
import org.bouncycastle.math.ec.ECPoint
import org.scalameter._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.keygen.IntAccumulator

import scala.util.Try

package object core {

  type PrivKey = BigInteger
  type PubKey = ECPoint
  type KeyPair = (PrivKey, PubKey)
  type Ciphertext = (ECPoint, ECPoint)
  type Randomness = BigInteger
  type Element = BigInteger
  type Point = ECPoint

  trait HasSize {
    def size: Int
  }

  val Zero: BigInteger = BigInteger.ZERO
  val One:  BigInteger = BigInteger.ONE

  // Generates deterministic sequence of elements in Zp field (p = orderOfBasePoint), which depends on seed
  case class DRNG (seed: Array[Byte], cs: Cryptosystem) {

    private val drng = new HashSP800DRBG(new SHA256Digest(), 256, new SingleEntropySourceProvider(cs.hash256(seed)).get(256), null, null)
    private val randBytes = new Array[Byte]((cs.orderOfBasePoint.bitLength.toFloat / 8).ceil.toInt)

    def getRand: Randomness = {
      drng.generate(randBytes, null, false)
      new BigInteger(randBytes).mod(cs.orderOfBasePoint)
    }
  }

  case class HybridCiphertext(encryptedKey: Ciphertext, encryptedMessage: Array[Byte])
    extends BytesSerializable {

    override type M = HybridCiphertext
    override val serializer: Serializer[M] = HybridCiphertextSerializer

    def size: Int = bytes.length
  }

  object HybridCiphertextSerializer extends Serializer[HybridCiphertext] {

    override def toBytes(obj: HybridCiphertext): Array[Byte] =
    {
      val encryptedKeyBytes1 = obj.encryptedKey._1.getEncoded(true)
      val encryptedKeyBytes2 = obj.encryptedKey._2.getEncoded(true)

      Bytes.concat(
        Ints.toByteArray(encryptedKeyBytes1.length),
        encryptedKeyBytes1,

        Ints.toByteArray(encryptedKeyBytes2.length),
        encryptedKeyBytes2,

        Ints.toByteArray(obj.encryptedMessage.length),
        obj.encryptedMessage
      )
    }

    override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[HybridCiphertext] = Try {

      val offset = IntAccumulator(0)

      val encryptedKeyBytes1Len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val encryptedKeyBytes1 = bytes.slice(offset.value, offset.plus(encryptedKeyBytes1Len))

      val encryptedKeyBytes2Len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val encryptedKeyBytes2 = bytes.slice(offset.value, offset.plus(encryptedKeyBytes2Len))

      val encryptedMessageLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val encryptedMessage = bytes.slice(offset.value, offset.plus(encryptedMessageLen))

      HybridCiphertext(
        (cs.decodePoint(encryptedKeyBytes1), cs.decodePoint(encryptedKeyBytes2)),
        encryptedMessage
      )
    }
  }

  case class HybridPlaintext(decryptedKey: Point, decryptedMessage: Array[Byte])
    extends BytesSerializable {

    override type M = HybridPlaintext
    override val serializer: Serializer[M] = HybridPlaintextSerializer

    def size: Int = bytes.length
  }

  object HybridPlaintextSerializer extends Serializer[HybridPlaintext] {

    override def toBytes(obj: HybridPlaintext): Array[Byte] =
    {
      val decryptedKeyBytes = obj.decryptedKey.getEncoded(true)

      Bytes.concat(
        Ints.toByteArray(decryptedKeyBytes.length),
        decryptedKeyBytes,
        Ints.toByteArray(obj.decryptedMessage.length),
        obj.decryptedMessage
      )
    }

    override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[HybridPlaintext] = Try {

      val offset = IntAccumulator(0)

      val decryptedKeyBytesLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val decryptedKeyBytes = bytes.slice(offset.value, offset.plus(decryptedKeyBytesLen))

      val decryptedMessageLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val decryptedMessage = bytes.slice(offset.value, offset.plus(decryptedMessageLen))

      HybridPlaintext(
        cs.decodePoint(decryptedKeyBytes),
        decryptedMessage
      )
    }
  }

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
