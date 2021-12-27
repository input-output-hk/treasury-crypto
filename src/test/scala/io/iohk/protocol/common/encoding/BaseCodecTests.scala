package io.iohk.protocol.common.encoding
import org.scalatest.FunSuite

class BaseCodecTests extends FunSuite {

  test("arbitrary_base"){
    val rng = scala.util.Random

    for(_ <- 0 until 10){
      val baseBitsSize = rng.nextInt(20) + 1
      val numberBitsSize = rng.nextInt(1000) + 1
//      println(s"${baseBitsSize} : ${numberBitsSize}")

      val base = Math.pow(2, baseBitsSize).toInt
      val number = BigInt(numberBitsSize, rng)
      assert(number == BaseCodec.decode(BaseCodec.encode(number, base)))
    }
  }
}
