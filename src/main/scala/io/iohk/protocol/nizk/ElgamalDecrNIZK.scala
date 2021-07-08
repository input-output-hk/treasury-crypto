package io.iohk.protocol.nizk

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption._
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.core.crypto.primitives.numbergenerator.SP800DRNG
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

/**
  * The ElGamalDecrNIZK allows to verify that the "ciphertext" is an encryption of the "plaintext" with the "privKey",
  * where (privKey, pubKey) constitutes a valid key pair
  */
object ElgamalDecrNIZK {

  def produceNIZK(ciphertext: ElGamalCiphertext, privKey: PrivKey)
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[DLEQStandardNIZKProof] = Try {

    //val randomness = dlogGroup.createRandomNumber
    // TODO: we need deterministic proofs (for DKG stuff). Is it secure to do it this way?
    // TODO: Seems like yes if the algorithm is not used twice with the same input params. If it does
    // TODO: then it will leak relevance between two proofs because the they would be the same. But this should be fine and maybe even useful.
    // TODO: Actually determinism is not really needed, but some DKG unit tests rely on this property.
    val randomness = BigInt(new SP800DRNG(privKey.toByteArray ++ ciphertext.bytes).nextBytes(128))

    val pubKey = dlogGroup.groupGenerator.pow(privKey).get
    val D = ciphertext.c1.pow(privKey).get
    DLEQStandardNIZK.produceNIZK(
      H1 = pubKey, H2 = D, G1 = dlogGroup.groupGenerator, G2 = ciphertext.c1,
      privKey, Option(randomness)).get
  }

  def verifyNIZK(pubKey: PubKey, ciphertext: ElGamalCiphertext, plaintext: GroupElement, proof: DLEQStandardNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {

    val D = ciphertext.c2.divide(plaintext).get
    DLEQStandardNIZK.verifyNIZK(pubKey, D, dlogGroup.groupGenerator, ciphertext.c1, proof)
  }.getOrElse(false)
}
