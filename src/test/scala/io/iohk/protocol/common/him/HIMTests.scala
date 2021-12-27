package io.iohk.protocol.common.him

import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

import scala.util.Random

class HIMTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  import context.group

  test("him_correctness"){
    // Number of beta points should be non lesser then the number of alpha points:
    // interpolated by (betas, output) polynomial should have a degree non-lesser than the polynomial interpolated by (alphas, input)
    (1 to 10).foreach{_ =>
      val alphas_num = Random.nextInt(20) + 1
      val betas_num = alphas_num + Random.nextInt(10)
      assert(HIM.testHIM(alphas_num, betas_num).isSuccess)
    }
  }
}
