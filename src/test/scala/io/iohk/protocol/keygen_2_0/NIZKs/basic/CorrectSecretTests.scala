package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectSecret.{Statement, Witness}
import org.scalatest.FunSuite

class CorrectSecretTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val g = context.group.groupGenerator

  import context.group

  test("CorrectSecret"){

    val (privKey, pubKey) = encryption.createKeyPair.get
    val mf = group.createRandomNumber
    val C0 = group.createRandomNumber

    val D0 = group.multiply(
      group.exponentiate(g, mf).get,
      group.exponentiate(crs, C0).get).get

    val mfCt = LiftedElGamalEnc.encrypt(pubKey, mf).get._1

    val cs = CorrectSecret(crs, mfCt, group)
    val proof = cs.prove(Witness(privKey, C0))

    assert(cs.verify(proof, Statement(pubKey, D0)))
  }
}
