package treasury.crypto.core.primitives.numbergenerator;

import org.scalatest.FunSuite

import scala.util.Random

class FieldElementSP800DRNGTest extends FunSuite {

    val r = new Array[Byte](32)
    Random.nextBytes(r)
    val p = BigInt(r).abs

    test("DRNG should produce the same elements for the same seed") {

        val drng1 = new FieldElementSP800DRNG("seedA".getBytes, p)
        val drng2 = new FieldElementSP800DRNG("seedA".getBytes, p)

        val rand1 = drng1.nextRand
        val rand2 = drng2.nextRand
        require(rand1 == rand2)

        val rand3 = drng1.nextRand
        val rand4 = drng2.nextRand
        require(rand3 == rand4)
    }

    test("DRNG should produce different elements from different seeds") {
        val drng1 = new FieldElementSP800DRNG("seedA".getBytes, p)
        val drng2 = new FieldElementSP800DRNG("seedB".getBytes, p)
        require(drng1.nextRand != drng2.nextRand)
    }

    test("DRNG should produce elements from GF(p)") {
        val drng1 = new FieldElementSP800DRNG("seedA".getBytes, p)
        for (i <- 1 to 50) require(drng1.nextRand < p)

        val p_small = 13
        val drng2 = new FieldElementSP800DRNG("seedB".getBytes, p_small)
        for (i <- 1 to 50) require(drng2.nextRand < p_small)
    }
}
