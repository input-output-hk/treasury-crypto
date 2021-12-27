package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.hybrid.{HybridCiphertext, HybridEncryption}
import io.iohk.core.crypto.encryption.{KeyPair, PubKey}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.signature.SchnorrSignature

case class Nomination(ephemeralPubKey     : PubKey,
                      ephemeralPrivKeyEnc : HybridCiphertext)

case class Nominator(context         : CryptoContext,
                     longTermPubKeys : Seq[PubKey]) {
  import context.{group, blockCipher}

  def selectHolder(): Nomination = {
    val rng = new scala.util.Random
    // select randomly a holder by its long term public key
    val selectedLongTermPubKey = longTermPubKeys.sorted.apply(rng.nextInt().abs % longTermPubKeys.size)

    val (ephemeralPrivKey, ephemeralPubKey) = encryption.createKeyPair.get
    val ephemeralPrivKeyEnc = HybridEncryption.encrypt(selectedLongTermPubKey, ephemeralPrivKey.toByteArray).get
    Nomination(ephemeralPubKey, ephemeralPrivKeyEnc)
  }
}

object Nominator
{
  def create(context         : CryptoContext,
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
      Option(Nominator(context, longTermPubKeys))
    } else {
      None
    }
  }
}
