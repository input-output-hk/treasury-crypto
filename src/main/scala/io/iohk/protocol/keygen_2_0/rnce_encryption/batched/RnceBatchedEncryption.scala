package io.iohk.protocol.keygen_2_0.rnce_encryption.batched

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.encoding.BaseCodec
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.RnceEncryptionLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.{RnceBatchedCiphertext, RnceBatchedPubKey, RnceBatchedRandomness, RnceBatchedSecretKey}

import scala.util.Try

object RnceBatchedEncryption {

  def keygen(params: RnceParams)
            (implicit dlogGroup: DiscreteLogGroup): (RnceBatchedSecretKey, RnceBatchedPubKey) = {
    val sk_pk = (0 until params.chunksMaxNum).map(_ => RnceEncryptionLight.keygen(params.crs))
    (RnceBatchedSecretKey(sk_pk.map(_._1)), RnceBatchedPubKey(sk_pk.map(_._2)))
  }

  def encrypt(pubKey: RnceBatchedPubKey,
              msg: BigInt,
              crs: RnceCrsLight)
             (implicit dlogGroup: DiscreteLogGroup): Try[(RnceBatchedCiphertext, RnceBatchedRandomness)] = Try {
    require(msg < dlogGroup.groupOrder)

    val msg_encoded = BaseCodec.encode(msg)
    val chunks_num = msg_encoded.seq.length
    require(pubKey.pubKeys.length >= chunks_num, "Insufficient public key length")

    val ct_rand = msg_encoded.seq.zip(pubKey.pubKeys.take(chunks_num)).map{
      msg_chunk_pk =>
        val (msg_chunk, pk) = msg_chunk_pk
        RnceEncryptionLight.encrypt(pk, msg_chunk, crs)
    }
    (RnceBatchedCiphertext(ct_rand.map(_._1)), RnceBatchedRandomness(ct_rand.map(_._2)))
  }

  def decrypt(secretKey: RnceBatchedSecretKey,
              ct: RnceBatchedCiphertext,
              crs: RnceCrsLight)
             (implicit dlogGroup: DiscreteLogGroup): Try[BigInt] = Try {
    val chunks_num = ct.C.length
    require(secretKey.secretKeys.length >= chunks_num, "Insufficient secret key length")

    BaseCodec.decode(
      ct.C.zip(secretKey.secretKeys.take(chunks_num)).map{
        ct_sk =>
          val (ct, sk) = ct_sk
          RnceEncryptionLight.decrypt(sk, ct, crs).get
      }
    )
  }
}
