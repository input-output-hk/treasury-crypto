package io.iohk.protocol.keygen.datastructures.round5_2

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.{IntAccumulator, SharedPublicKey}

import scala.util.Try

case class R5_2Data(
                     issuerID:            Int,
                     sharedPublicKey:     SharedPublicKey,
                     violatorsSecretKeys: Array[SecretKey]
                   )

  extends HasSize with BytesSerializable {

  override type M = R5_2Data
  override type DECODER = CryptoContext
  override val serializer: Serializer[M, DECODER] = R5_2DataSerializer

  def size: Int = bytes.length

  def canEqual(a: Any): Boolean = a.isInstanceOf[M]

  override def equals(that: Any): Boolean =
    that match {
      case that: M => that.canEqual(this) && this.hashCode == that.hashCode
      case _ => false
    }

  override def hashCode: Int = {

    import java.util.zip.CRC32

    val checksum = new CRC32
    checksum.update(bytes, 0, bytes.length)
    checksum.getValue.toInt
  }
}

object R5_2DataSerializer extends Serializer[R5_2Data, CryptoContext] {

  override def toBytes(obj: R5_2Data): Array[Byte] = {

    val violatorsSecretKeysBytes = obj.violatorsSecretKeys.foldLeft(Array[Byte]()){(acc, sk) => acc ++ Ints.toByteArray(sk.size) ++ sk.bytes}

    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Ints.toByteArray(obj.sharedPublicKey.length),
      obj.sharedPublicKey,
      Ints.toByteArray(obj.violatorsSecretKeys.length),
      violatorsSecretKeysBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], ctxOpt: Option[CryptoContext]): Try[R5_2Data] = Try {
    val ctx = ctxOpt.get
    val offset = IntAccumulator(0)

    val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val sharedPublicKeyLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
    val sharedPublicKeyBytes = bytes.slice(offset.value, offset.plus(sharedPublicKeyLen))

    val violatorsSecretKeysLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

    val violatorsSecretKeys = for (_ <- 0 until violatorsSecretKeysLen) yield {
      val violatorsSecretKeyLen = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val violatorsSecretKeyBytes = bytes.slice(offset.value, offset.plus(violatorsSecretKeyLen))
      SecretKeySerializer.parseBytes(violatorsSecretKeyBytes, Option(ctx)).get
    }

    R5_2Data(issuerID, sharedPublicKeyBytes, violatorsSecretKeys.toArray)
  }
}
