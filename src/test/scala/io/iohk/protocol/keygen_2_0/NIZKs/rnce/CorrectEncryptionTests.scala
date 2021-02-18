package io.iohk.protocol.keygen_2_0.NIZKs.rnce

import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.CorrectSecret.Witness
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import org.scalatest.FunSuite

class CorrectEncryptionTests  extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group

  private val rnce_crs = RnceCrsLight(g1 = dlogGroup.createRandomGroupElement.get, g2 = dlogGroup.createRandomGroupElement.get)
  private val cs_crs = CorrectSecret.CRS(rnce_crs, dlogGroup.createRandomGroupElement.get)

  import context.group

  test("CorrectSecret"){
    val s = group.createRandomNumber
    val s_ = group.createRandomNumber

    val proof = CorrectSecret(cs_crs, group).prove(Witness(s, s_))
    assert(CorrectSecret(cs_crs, group).verify(proof))
  }
}
