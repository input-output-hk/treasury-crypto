package io.iohk.protocol.common.signature

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.signature.SchnorrSignature
import org.scalatest.FunSuite

class SchnorrSignatureTests extends FunSuite {
  private val context = new CryptoContext(Option( CryptoContext.generateRandomCRS))
  import context.group

  test("functionality_and_serialization"){
    val (privKey, pubKey) = encryption.createKeyPair.get
    val message = context.group.createRandomNumber.toByteArray
    val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

    val signature = SchnorrSignature.sign(privKey, message, sha)
    assert(SchnorrSignature.verify(pubKey, signature, message, sha))

    val signature_ = SchnorrSignature.Serializer.parseBytes(signature.bytes).get
    assert(signature.e.sameElements(signature_.e))
    assert(signature.s.equals(signature_.s))
    assert(SchnorrSignature.verify(pubKey, signature_, message, sha))
  }
}
