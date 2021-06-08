package io.iohk.protocol.nizk

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption._
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.encryption.hybrid.HybridPlaintext
import io.iohk.core.crypto.encryption.hybrid.dlp.DLPHybridCiphertext
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.core.crypto.primitives.numbergenerator.SP800DRNG
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

/**
  * The DLPHybridDecrNIZK allows to verify that the "ciphertext" is an encryption of the "plaintext" that was done with the DLPHybridEncryption scheme,
  * where (privKey, pubKey) constitutes a valid key pair
  */
object DLPHybridDecrNIZK {

  def produceNIZK(ciphertext: DLPHybridCiphertext, privKey: PrivKey)
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[DLPHybridDecrNIZKProof] = Try {

    //val w = dlogGroup.createRandomNumber
    // TODO: we need deterministic proofs (for DKG stuff). Is it secure to do it this way?
    // TODO: Seems like yes if the algorithm is not used twice with the same input params. If it does
    // TODO: then it will leak relevance between two proofs because the they would be the same. But this should be fine and maybe even useful.
    // TODO: Actually determinism is not really needed, but some DKG unit tests rely on this property.
    val randomness = new SP800DRNG(privKey.toByteArray ++ ciphertext.bytes).nextBytes(128)

    val w = BigInt(randomness)
    val A1 = dlogGroup.groupGenerator.pow(w).get
    val A2 = ciphertext.C1.pow(w).get
    val C2 = ciphertext.C1.pow(privKey).get
    val pubKey = dlogGroup.groupGenerator.pow(privKey).get

    val e = BigInt(
      hashFunction.hash {
        ciphertext.bytes ++
        C2.bytes ++
        A1.bytes ++
        A2.bytes ++
        pubKey.bytes
      }).mod(dlogGroup.groupOrder)

    val z = (privKey * e + w) mod dlogGroup.groupOrder

    DLPHybridDecrNIZKProof(C2, A1, A2, z)
  }

  def verifyNIZK(pubKey: PubKey, ciphertext: DLPHybridCiphertext, decryptedMessage: Array[Byte], proof: DLPHybridDecrNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, blockCipher: BlockCipher, hashFunction: CryptographicHash): Boolean = Try {

    val e = BigInt(
      hashFunction.hash {
        ciphertext.bytes ++
        proof.C2.bytes ++
        proof.A1.bytes ++
        proof.A2.bytes ++
        pubKey.bytes
      }).mod(dlogGroup.groupOrder)

    val k = blockCipher.generateKey(proof.C2.bytes)
    val c = blockCipher.encrypt(k, decryptedMessage).get
    require(c.bytes.sameElements(ciphertext.encryptedMessage.bytes))

    val gz = dlogGroup.groupGenerator.pow(proof.z).get
    val heA1 = pubKey.pow(e).get.multiply(proof.A1).get

    val C1z = ciphertext.C1.pow(proof.z).get
    val C2eA2 = proof.C2.pow(e).get.multiply(proof.A2).get

    gz.equals(heA1) && C1z.equals(C2eA2)
  }.getOrElse(false)
}

case class DLPHybridDecrNIZKProof(C2:GroupElement, A1: GroupElement, A2: GroupElement, z: BigInt) extends BytesSerializable {

  override type M = DLPHybridDecrNIZKProof
  override type DECODER = DiscreteLogGroup
  override val serializer = DLPHybridDecrNIZKProofSerializer

  def size: Int = bytes.length
}

object DLPHybridDecrNIZKProofSerializer extends Serializer[DLPHybridDecrNIZKProof, DiscreteLogGroup] {

  override def toBytes(obj: DLPHybridDecrNIZKProof): Array[Byte] = {
    val C2Bytes = obj.C2.bytes
    val A1Bytes = obj.A1.bytes
    val A2Bytes = obj.A2.bytes
    val zBytes = obj.z.toByteArray

    Bytes.concat(Array(C2Bytes.length.toByte), C2Bytes,
      Array(A1Bytes.length.toByte), A1Bytes,
      Array(A2Bytes.length.toByte), A2Bytes,
      Array(zBytes.length.toByte), zBytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[DLPHybridDecrNIZKProof] = Try {
    val group = decoder.get
    val C2Len = bytes(0)
    val C2 = group.reconstructGroupElement(bytes.slice(1,C2Len+1)).get
    var pos = C2Len + 1

    val A1Len = bytes(pos)
    val A1 = group.reconstructGroupElement(bytes.slice(pos+1,A1Len+pos+1)).get
    pos += (A1Len + 1)

    val A2Len = bytes(pos)
    val A2 = group.reconstructGroupElement(bytes.slice(pos+1,A2Len+pos+1)).get
    pos += (A2Len + 1)

    val zLen = bytes(pos)
    val z = BigInt(bytes.slice(pos+1, pos+1+zLen))

    DLPHybridDecrNIZKProof(C2, A1, A2, z)
  }
}
