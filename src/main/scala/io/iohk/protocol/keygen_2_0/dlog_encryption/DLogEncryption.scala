package io.iohk.protocol.keygen_2_0.dlog_encryption

import io.iohk.core.crypto.encryption.{PrivKey, PubKey, Randomness}
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.encoding.BaseCodec

import scala.util.Try

case class DLogRandomness(R: Seq[Randomness]) // is needed for NIZKs as a witness data

object DLogEncryption {

  def encrypt(msg: BigInt,
              pubKey: PubKey)
             (implicit dlogGroup: DiscreteLogGroup): Try[(DLogCiphertext, DLogRandomness)] = Try {
    require(msg < dlogGroup.groupOrder)

    val ct_rand = BaseCodec.encode(msg).seq.map(p => LiftedElGamalEnc.encrypt(pubKey, p).get)
    (DLogCiphertext(ct_rand.map(_._1)), DLogRandomness(ct_rand.map(_._2)))
  }

  def decrypt(ct: DLogCiphertext,
              privKey: PrivKey)
             (implicit dlogGroup: DiscreteLogGroup): Try[BigInt] = Try {
    BaseCodec.decode(
      ct.C.map(LiftedElGamalEnc.decrypt(privKey, _).get)
    )
  }
}
