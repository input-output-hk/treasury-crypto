package io.iohk.protocol.keygen_2_0.rnce_encryption

import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.rnce_encryption.RnceEncryption._
import org.scalatest.FunSuite

class RnceEncryptionTests extends FunSuite{
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group
  private val n = dlogGroup.groupOrder
  private val msg = dlogGroup.createRandomNumber.mod(10000) // message should't be too big for discreteLog to be feasible

  import context.group

  test("encryption_decryption"){
    val (sk, pk, _) = keygen()
    assert(decrypt(sk, encrypt(pk, msg)).get.equals(msg))
  }

  test("simulation"){
    val (sk, pk, aux) = keygen()
    val fakeCt = fakeCiphertext(sk, pk)
    val fakeSk = fakeSecretKey(sk, aux, msg)
    assert(decrypt(fakeSk, fakeCt).get.equals(msg))
  }
}
