package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto.TimeUtils
import treasury.crypto.nizk.shvzk.{SHVZKGen, SHVZKVerifier}

/* Benchmarking Unit Vector ZK with log size communication */
class SHVZKPerformance {

  def run() = {
    val shvzkTest = new SHVZKTest()

    val unitVectorSize = List(255, 511, 1023, 2047, 4095)
    for (size <- unitVectorSize) {
      println("Running test for unit vector of size " + size + " ...")
      val (uv, rand) = TimeUtils.time("\tUV creation: ", shvzkTest.createUnitVector(size, 3))
      val proof = TimeUtils.time(
        "\tSHV NIZK creation: ",
        new SHVZKGen(shvzkTest.cs, shvzkTest.pubKey, uv, 3, rand).produceNIZK())
      val verified = TimeUtils.time(
        "\tSHV NIZK verification",
        new SHVZKVerifier(shvzkTest.cs, shvzkTest.pubKey, uv, proof).verifyProof())
      println("\tVerified: " + verified)
      val proofsize: Int =
        proof.R.toByteArray.size +
        proof.zwv.size * proof.zwv(0)._1.toByteArray.size * 3 +
        proof.Dk.size * proof.Dk(0)._1.getEncoded(true).size * 2 +
        proof.IBA.size * proof.IBA(0)._1.getEncoded(true).size * 3
      println("\tNIZK Proof size: " + proofsize + " bytes")
    }
  }
}

object SHVZKPerformance {
  def main(args: Array[String]) {
    new SHVZKPerformance().run
  }
}