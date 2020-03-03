package io.iohk.core.primitives.numbergenerator

import org.scalatest.FunSuite

class SP800DRNGTest extends FunSuite {

  test("DRNG should produce the same sequence of elements for the same seed") {
    val drng1 = new SP800DRNG("seedA".getBytes)
    val drng2 = new SP800DRNG("seedA".getBytes)
    val seq1 = drng1.nextBytes(10)
    val seq2 = drng2.nextBytes(5)

    require(seq1.take(5).sameElements(seq2))

    val seq1next = drng1.nextBytes(5)
    val seq2next = drng2.nextBytes(5)

    require(seq1next.sameElements(seq2next))
  }

  test("DRNG should produce different elements from different seeds") {
    val drng1 = new SP800DRNG("seedA".getBytes)
    val drng2 = new SP800DRNG("seedB".getBytes)
    val seq1 = drng1.nextBytes(16)
    val seq2 = drng2.nextBytes(16)

    require(seq1.sameElements(seq2) == false)
  }
}