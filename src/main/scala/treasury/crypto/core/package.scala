package treasury.crypto

import java.math.BigInteger

import org.bouncycastle.math.ec.ECPoint
import org.scalameter._

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

  val Zero: BigInteger = BigInteger.valueOf(0)
  val One:  BigInteger = BigInteger.valueOf(1)

  case class HybridCiphertext(encryptedKey: Ciphertext, encryptedMessage: Array[Byte])
  {
    def size: Int =
    {
      encryptedKey._1.getEncoded(true).size +
      encryptedKey._2.getEncoded(true).size
      encryptedMessage.size
    }
  }
  case class HybridPlaintext (decryptedKey: Point, decryptedMessage: Array[Byte])
  {
    def size: Int =
    {
      decryptedKey.getEncoded(true).size +
      decryptedMessage.size
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

  object SizeUtils
  {
    def getSize[T <: HasSize](vector: Seq[T]): Int =
    {
      val maxSize = vector.maxBy(_.size).size
      val totalSize = vector.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

      println(maxSize + " B;\t" + totalSize + " B")

      totalSize
    }
  }
}
