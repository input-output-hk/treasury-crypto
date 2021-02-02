package io.iohk.protocol.keygen_2_0.rnce_encryption

import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.full.RnceEncryption
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.RnceEncryptionLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}
import org.scalatest.FunSuite

class RnceEncryptionTests extends FunSuite{
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group

  private val msg = dlogGroup.createRandomNumber
  private val msg_small = msg.mod(10000) // message not too big for discreteLog to be feasible

  private val alpha = dlogGroup.createRandomNumber
  private val crs_light = RnceCrsLight(g1 = crs, g2 = dlogGroup.exponentiate(crs, alpha).get) // CRS for simulatable encryption due to g2 = g1^alpha and alpha is known
//  private val crs_light = RnceCrsLight(CryptoContext.generateRandomCRS, CryptoContext.generateRandomCRS)

  import context.group

  private val params = RnceParams(crs_light)

  test("encryption_decryption_basic"){
    val (sk, pk, _) = RnceEncryption.keygen()
    assert(RnceEncryption.decrypt(sk, RnceEncryption.encrypt(pk, msg_small)).get.equals(msg_small))

    val (sk_light, pk_light) = RnceEncryptionLight.keygen(crs_light)
    assert(RnceEncryptionLight.decrypt(sk_light, RnceEncryptionLight.encrypt(pk_light, msg_small, crs_light)._1, crs_light).get.equals(msg_small))
  }

  test("simulation_full"){
    import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.full.RnceEncryption._
    val (sk, pk, aux) = keygen()
    val fakeCt = fakeCiphertext(sk, pk)
    val fakeSk = fakeSecretKey(sk, aux, msg_small)
    assert(decrypt(fakeSk, fakeCt).get.equals(msg_small))
  }

  test("simulation_light"){
    import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.RnceEncryptionLight._
    val (sk, pk) = keygen(crs_light)
    val fakeCt = fakeCiphertext(sk, pk, crs_light)
    val fakeSk = fakeSecretKey(sk, alpha, msg_small)
    assert(decrypt(fakeSk, fakeCt, crs_light).get.equals(msg_small))
  }

  test("encryption_decryption_batched"){
    val (sk, pk) = RnceBatchedEncryption.keygen(params)
    assert(msg == RnceBatchedEncryption.decrypt(sk, RnceBatchedEncryption.encrypt(pk, msg, crs_light).get._1, crs_light).get)
  }

  test("serialization_light"){
    import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.RnceEncryptionLight._

    val (sk, pk) = keygen(crs_light)
    val ct = encrypt(pk, msg_small, crs_light)._1

    val sk_bytes = sk.bytes
    val pk_bytes = pk.bytes
    val ct_bytes = ct.bytes
    val crs_bytes = crs_light.bytes

    import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCiphertextLightSerializer, RnceCrsLightSerializer, RncePublicKeyLightSerializer, RnceSecretKeyLightSerializer}

    assert(RnceSecretKeyLightSerializer.parseBytes(sk_bytes, Some(dlogGroup)).get.bytes.sameElements(sk_bytes))
    assert(RncePublicKeyLightSerializer.parseBytes(pk_bytes, Some(dlogGroup)).get.bytes.sameElements(pk_bytes))
    assert(RnceCiphertextLightSerializer.parseBytes(ct_bytes, Some(dlogGroup)).get.bytes.sameElements(ct_bytes))
    assert(RnceCrsLightSerializer.parseBytes(crs_bytes, Some(dlogGroup)).get.bytes.sameElements(crs_bytes))
  }

  test("serialization_batched"){
    import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.RnceBatchedEncryption._

    val (sk, pk) = keygen(params)
    val ct = encrypt(pk, msg, crs_light).get._1

    val sk_bytes = sk.bytes
    val pk_bytes = pk.bytes
    val ct_bytes = ct.bytes

    import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.{RnceBatchedSecretKeySerializer, RnceBatchedPubKeySerializer, RnceBatchedCiphertextSerializer}

    assert(RnceBatchedSecretKeySerializer.parseBytes(sk_bytes, Some(dlogGroup)).get.bytes.sameElements(sk_bytes))
    assert(RnceBatchedPubKeySerializer.parseBytes(pk_bytes, Some(dlogGroup)).get.bytes.sameElements(pk_bytes))
    assert(RnceBatchedCiphertextSerializer.parseBytes(ct_bytes, Some(dlogGroup)).get.bytes.sameElements(ct_bytes))
  }
}
