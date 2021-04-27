package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption.hybrid.{HybridCiphertext, HybridEncryption}
import io.iohk.core.crypto.encryption.{KeyPair, PubKey}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.rnce_encryption.RncePubKey
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}
import io.iohk.protocol.keygen_2_0.signature.SchnorrSignature

case class Nomination(ephemeralPubKey     : RncePubKey,
                      ephemeralPrivKeyEnc : HybridCiphertext)
object Nomination
{
  def create(context: CryptoContext,
             keygenParams: RnceParams,
             receiverPubKey: PubKey): Nomination = {
    import context.{group, blockCipher}

    val (ephemeralPrivKey, ephemeralPubKey) = RnceBatchedEncryption.keygen(keygenParams)
    val ephemeralPrivKeyEnc = HybridEncryption.encrypt(receiverPubKey, ephemeralPrivKey.bytes).get
    Nomination(ephemeralPubKey, ephemeralPrivKeyEnc)
  }
}

case class Nominator(context         : CryptoContext,
                     keygenParams    : RnceParams,
                     longTermPubKeys : Seq[PubKey])
{
  def selectHolder(): Nomination = {
    val rng = new scala.util.Random
    // select randomly a holder by its long term public key
    val selectedLongTermPubKey = longTermPubKeys.sorted.apply(rng.nextInt().abs % longTermPubKeys.size)
   Nomination.create(context, keygenParams, selectedLongTermPubKey)
  }
}

object Nominator
{
  def create(context         : CryptoContext,
             keygenParams    : RnceParams,
             ownKeyPair      : KeyPair, // own long-term key pair
             stake           : Int,
             thresholdCoeff  : BigInt,
             commonSeed      : BigInt,
             longTermPubKeys : Seq[PubKey]): Option[Nominator] = {
    val isNominator = {
      val sha = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
      val (ownPrivKey, ownPubKey) = ownKeyPair
      import context.group
      val hash = BigInt(1, sha.hash(ownPubKey.bytes ++ SchnorrSignature.sign(ownPrivKey, commonSeed.toByteArray, sha).bytes))
      val target = BigInt(stake.abs) * thresholdCoeff.abs
      hash <= target
    }
    if(isNominator){
      Option(Nominator(context, keygenParams, longTermPubKeys))
    } else {
      None
    }
  }
}
