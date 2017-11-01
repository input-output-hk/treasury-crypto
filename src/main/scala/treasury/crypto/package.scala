package treasury

import java.math.BigInteger

import org.bouncycastle.math.ec.ECPoint
import org.scalameter._

package object crypto {

  type PrivKey = BigInteger
  type PubKey = ECPoint
  type Ciphertext = (ECPoint, ECPoint)
  type Randomness = BigInteger
  type Element = BigInteger
  type Point = ECPoint

  val Zero = BigInteger.valueOf(0)
  val One = BigInteger.valueOf(1)

  case class TallyResult(val yes: BigInteger, val no: BigInteger, val abstain: BigInteger)

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
}
