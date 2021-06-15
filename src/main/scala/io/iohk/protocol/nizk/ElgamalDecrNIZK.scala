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
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[ElgamalDecrNIZKProof] = Try {

    //val w = dlogGroup.createRandomNumber
    // TODO: we need deterministic proofs (for DKG stuff). Is it secure to do it this way?
    // TODO: Seems like yes if the algorithm is not used twice with the same input params. If it does
    // TODO: then it will leak relevance between two proofs because the they would be the same. But this should be fine and maybe even useful.
    // TODO: Actually determinism is not really needed, but some DKG unit tests rely on this property.
    val randomness = new SP800DRNG(privKey.toByteArray ++ ciphertext.bytes).nextBytes(128)

    val w = BigInt(randomness)
    val A1 = dlogGroup.groupGenerator.pow(w).get
    val A2 = ciphertext.c1.pow(w).get
    val D = ciphertext.c1.pow(privKey).get
    val pubKey = dlogGroup.groupGenerator.pow(privKey).get

    val e = BigInt(
      hashFunction.hash {
        pubKey.bytes ++
        ciphertext.bytes ++
        D.bytes ++
        A1.bytes ++
        A2.bytes
      }).mod(dlogGroup.groupOrder)

    val z = (privKey * e + w) mod dlogGroup.groupOrder

    ElgamalDecrNIZKProof(A1, A2, z)
  }

  def verifyNIZK(pubKey: PubKey, ciphertext: ElGamalCiphertext, plaintext: GroupElement, proof: ElgamalDecrNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {

    val D = ciphertext.c2.divide(plaintext).get
    val e = BigInt(
      hashFunction.hash {
        pubKey.bytes ++
        ciphertext.bytes ++
        D.bytes ++
        proof.A1.bytes ++
        proof.A2.bytes
      }).mod(dlogGroup.groupOrder)

    val gz = dlogGroup.groupGenerator.pow(proof.z).get
    val heA1 = pubKey.pow(e).get.multiply(proof.A1).get

    val C1z = ciphertext.c1.pow(proof.z).get
    val DeA2 = D.pow(e).get.multiply(proof.A2).get

    gz.equals(heA1) && C1z.equals(DeA2)
  }.getOrElse(false)
}

case class ElgamalDecrNIZKProof(A1: GroupElement, A2: GroupElement, z: BigInt) extends BytesSerializable {

  override type M = ElgamalDecrNIZKProof
  override type DECODER = DiscreteLogGroup
  override val serializer = ElgamalDecrNIZKProofSerializer

  def size: Int = bytes.length
}

object ElgamalDecrNIZKProofSerializer extends Serializer[ElgamalDecrNIZKProof, DiscreteLogGroup] {

  override def toBytes(obj: ElgamalDecrNIZKProof): Array[Byte] = {
    val A1Bytes = obj.A1.bytes
    val A2Bytes = obj.A2.bytes
    val zBytes = obj.z.toByteArray

    Bytes.concat(Array(A1Bytes.length.toByte), A1Bytes,
      Array(A2Bytes.length.toByte), A2Bytes,
      Array(zBytes.length.toByte), zBytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[ElgamalDecrNIZKProof] = Try {
    val group = decoder.get
    val A1Len = bytes(0)
    val A1 = group.reconstructGroupElement(bytes.slice(1,A1Len+1)).get
    var pos = A1Len + 1

    val A2Len = bytes(pos)
    val A2 = group.reconstructGroupElement(bytes.slice(pos+1,A2Len+pos+1)).get
    pos = pos + A2Len + 1

    val zLen = bytes(pos)
    val z = BigInt(bytes.slice(pos+1, pos+1+zLen))

    ElgamalDecrNIZKProof(A1, A2, z)
  }
}
