package treasury.crypto.nizk

import org.scalatest.FunSuite
import treasury.crypto.Utils
import treasury.crypto.nizk.shvzk.{SHVZKGen, SHVZKVerifier}

class SHVZKPerformance extends FunSuite {

  test("Unit Vector ZK with log size communication") {
    val shvzkTest = new SHVZKTest()

    val unitVectorSize = List(255, 511, 1023, 2047, 4095)
    for (size <- unitVectorSize) {
      println("Running test for unit vector of size " + size + " ...")
      val (uv, rand) = Utils.time("     UV creation: ", shvzkTest.createUnitVector(size, 3))
      val proof = Utils.time(
        "     SHV NIZK creation: ",
        new SHVZKGen(shvzkTest.cs, shvzkTest.pubKey, uv, 3, rand).produceNIZK())
      val verified = Utils.time(
        "     SHV NIZK verification",
        new SHVZKVerifier(shvzkTest.cs, shvzkTest.pubKey, uv, proof).verifyProof())
      println("     Verified: " + verified)
      val proofsize: Int =
        proof.R.size +
        proof.zwv.size * proof.zwv(0)._1.size * 3 +
        proof.Dk.size * proof.Dk(0)._1.size * 2 +
        proof.IBA.size * proof.IBA(0)._1.size * 3
      println("     NIZK Proof size: " + proofsize + " bytes")
    }
  }
}
