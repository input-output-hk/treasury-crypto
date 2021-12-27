package io.iohk.protocol.common.signature

import com.google.common.primitives.Ints
import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.core.serialization.{BytesSerializable, NODECODER, Serializer}

import scala.util.Try

object SchnorrSignature{

  def sign(privKey: PrivKey, msg: Array[Byte], hashAlgorithm: CryptographicHash)
          (implicit dlogGroup: DiscreteLogGroup): Signature = {
    val k = dlogGroup.createRandomNumber
    val r = dlogGroup.exponentiate(dlogGroup.groupGenerator, k).get

    val e = hashAlgorithm.hash(r.bytes ++ msg)
    val s = (k - privKey * BigInt(e)).mod(dlogGroup.groupOrder)

    Signature(s, e)
  }

  def verify(pubKey: PubKey, signature: Signature, msg: Array[Byte], hashAlgorithm: CryptographicHash)
            (implicit dlogGroup: DiscreteLogGroup): Boolean = {
    val r_v = dlogGroup.multiply(
      dlogGroup.exponentiate(dlogGroup.groupGenerator, signature.s).get,
      dlogGroup.exponentiate(pubKey, BigInt(signature.e)).get
    ).get
    val e_v = hashAlgorithm.hash(r_v.bytes ++ msg)

    e_v.sameElements(signature.e)
  }

  case class Signature(s: BigInt, e: Array[Byte]) extends BytesSerializable{
    override type M = Signature
    override type DECODER = NODECODER
    override def serializer: Serializer[M, DECODER] = Serializer
  }

  object Serializer extends Serializer[Signature, NODECODER] {
    override def toBytes(signature: Signature): Array[Byte] = {
      val s_bytes = signature.s.toByteArray
      Ints.toByteArray(s_bytes.length) ++
      s_bytes ++
      signature.e
    }
    override def parseBytes(bytes: Array[Byte], d: Option[NODECODER] = None): Try[Signature] = Try {
      val s_bytes_len = Ints.fromByteArray(bytes)
      val s_bytes = bytes.slice(Ints.BYTES, Ints.BYTES + s_bytes_len)
      val e = bytes.drop(Ints.BYTES + s_bytes_len)
      Signature(BigInt(s_bytes), e)
    }
  }
}
