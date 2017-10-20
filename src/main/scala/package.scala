
package object common {

  type PrivKey = Array[Byte]
  type PubKey = Array[Byte]
  type Ciphertext = (Array[Byte], Array[Byte])
  type Message = Int
  type Randomness = Array[Byte]
  type Element = Array[Byte]

  case class TallyResult(val yes: Int, val no: Int, val abstain: Int)

  object VoteCases extends Enumeration {
    val Yes, No, Abstain = Value
  }

  object Utils {
    def time[R](block: => R): R = {
      val t0 = System.nanoTime()
      val result = block
      val t1 = System.nanoTime()
      println("Elapsed time: " + (t1-t0)/1000000 + " ms")
      result
    }

    def time[R](msg: String, block: => R): R = {
      val t0 = System.nanoTime()
      val result = block
      val t1 = System.nanoTime()
      println(msg + " " + (t1-t0)/1000000 + " ms")
      result
    }
  }
}
