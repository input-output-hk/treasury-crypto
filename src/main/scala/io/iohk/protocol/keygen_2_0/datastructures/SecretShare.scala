package io.iohk.protocol.keygen_2_0.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.encryption.hybrid.{HybridCiphertext, HybridCiphertextSerializer}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipher
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.common.dlog_encryption.{DLogCiphertext, DLogCiphertextSerializer}

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

case class SecretShare(receiverID: Int,
                       dealerPoint: Int = 0, // point corresponding to a share which subshare is encrypted here; Needed for Lagrange coefficient 'Lambda' computation at re-sharing phase
                       S: DLogCiphertext)    // encrypted share of a partial secret at DKG phase or encrypted subshare of share at Maintaining phase
  extends HasSize with BytesSerializable {

  override type M = SecretShare
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = SecretShareSerializer

  def size: Int = bytes.length
}

object SecretShareSerializer extends Serializer[SecretShare, DiscreteLogGroup] {

  override def toBytes(obj: SecretShare): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.receiverID),
      Ints.toByteArray(obj.dealerPoint),
      obj.S.bytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[SecretShare] = Try {
    SecretShare(
      Ints.fromByteArray(bytes.slice(0, 4)),
      Ints.fromByteArray(bytes.slice(4, 8)),
      DLogCiphertextSerializer.parseBytes(bytes.slice(8, bytes.length), decoder).get)
  }
}