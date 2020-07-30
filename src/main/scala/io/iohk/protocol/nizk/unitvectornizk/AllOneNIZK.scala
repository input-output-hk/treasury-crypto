package io.iohk.protocol.nizk.unitvectornizk

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.core.serialization.{BytesSerializable, Serializer}

import scala.util.Try

/**
  * An efficient non-interactive zero-knowledge proof proving that in the array of ciphertexts every element encrypts one
  */
object AllOneNIZK {

  def produceNIZK(pubKey: PubKey, ciphertexts: Seq[(ElGamalCiphertext, Randomness)])
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[AllOneNIZKProof] = Try {

    val ciphertextsBytes = ciphertexts.foldLeft(Array[Byte]()) { (acc, c) =>
      acc ++ c._1.bytes
    }
    val rho = BigInt(hashFunction.hash(pubKey.bytes ++ ciphertextsBytes)).mod(dlogGroup.groupOrder)

    val (e1, e2) = ciphertexts.zipWithIndex.foldLeft((dlogGroup.groupIdentity, dlogGroup.groupIdentity)) { (acc, elem) =>
      val (e1Acc, e2Acc) = acc
      val ((c, _), i) = elem
      val rho_i = rho.pow(i + 1).mod(dlogGroup.groupOrder)
      val c2_g = c.c2.divide(dlogGroup.groupGenerator).get
      (e1Acc.multiply(c.c1.pow(rho_i).get).get,
       e2Acc.multiply(c2_g.pow(rho_i).get).get)
    }

    val t = dlogGroup.createRandomNumber
    val T1 = dlogGroup.groupGenerator.pow(t).get
    val T2 = pubKey.pow(t).get

    val e = BigInt(hashFunction.hash(
        pubKey.bytes ++
        ciphertextsBytes ++
        e1.bytes ++
        e2.bytes ++
        T1.bytes ++
        T2.bytes))

    val sum = ciphertexts.zipWithIndex.foldLeft(BigInt(0)) { (acc, elem) =>
      val ((_, r), i) = elem
      val rho_i = rho.pow(i + 1).mod(dlogGroup.groupOrder)
      acc + (r * rho_i)
    }
    val z = t + (e * sum)

    AllOneNIZKProof(T1, T2, z)
  }

  def verifyNIZK(pubKey: PubKey, ciphertexts: Seq[ElGamalCiphertext], proof: AllOneNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {
    val ciphertextsBytes = ciphertexts.foldLeft(Array[Byte]()) { (acc, c) =>
      acc ++ c.bytes
    }
    val rho = BigInt(hashFunction.hash(pubKey.bytes ++ ciphertextsBytes)).mod(dlogGroup.groupOrder)

    val (e1, e2) = ciphertexts.zipWithIndex.foldLeft((dlogGroup.groupIdentity, dlogGroup.groupIdentity)) { (acc, elem) =>
      val (e1Acc, e2Acc) = acc
      val (c, i) = elem
      val rho_i = rho.pow(i + 1).mod(dlogGroup.groupOrder)
      val c2_g = c.c2.divide(dlogGroup.groupGenerator).get
      (e1Acc.multiply(c.c1.pow(rho_i).get).get,
       e2Acc.multiply(c2_g.pow(rho_i).get).get)
    }

    val e = BigInt(hashFunction.hash(
      pubKey.bytes ++
        ciphertextsBytes ++
        e1.bytes ++
        e2.bytes ++
        proof.T1.bytes ++
        proof.T2.bytes))

    val g_z = dlogGroup.groupGenerator.pow(proof.z)
    val E1_e_T1 = e1.pow(e).get * proof.T1
    require(g_z == E1_e_T1)

    val h_z = pubKey.pow(proof.z)
    val E2_e_T2 = e2.pow(e).get * proof.T2
    require(h_z == E2_e_T2)

  }.isSuccess
}

case class AllOneNIZKProof(T1: GroupElement, T2: GroupElement, z: BigInt) extends BytesSerializable {

  override type M = AllOneNIZKProof
  override type DECODER = DiscreteLogGroup
  override val serializer = AllOneNIZKProofSerializer

  def size: Int = bytes.length
}

object AllOneNIZKProofSerializer extends Serializer[AllOneNIZKProof, DiscreteLogGroup] {

  override def toBytes(obj: AllOneNIZKProof): Array[Byte] = {
    val T1Bytes = obj.T1.bytes
    val T2Bytes = obj.T2.bytes
    val zBytes = obj.z.toByteArray

    Bytes.concat(Array(T1Bytes.length.toByte), T1Bytes,
      Array(T2Bytes.length.toByte), T2Bytes,
      Array(zBytes.length.toByte), zBytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[AllOneNIZKProof] = Try {
    val group = decoder.get
    val T1Len = bytes(0)
    val T1 = group.reconstructGroupElement(bytes.slice(1,T1Len+1)).get
    var pos = T1Len + 1

    val T2Len = bytes(pos)
    val T2 = group.reconstructGroupElement(bytes.slice(pos+1,T2Len+pos+1)).get
    pos = pos + T2Len + 1

    val zLen = bytes(pos)
    val z = BigInt(bytes.slice(pos+1, pos+1+zLen))

    AllOneNIZKProof(T1, T2, z)
  }
}
