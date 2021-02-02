package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.{RnceBatchedPubKey, RnceBatchedSecretKey}

import scala.util.Try

package object rnce_encryption {
    type RncePubKey = RnceBatchedPubKey
    type RncePrivKey = RnceBatchedSecretKey
    type RnceKeyPair = (RncePrivKey, RncePubKey)
    type RnceRandomness = BigInt

    def createRnceKeyPair(params: RnceParams)(implicit dlogGroup: DiscreteLogGroup): Try[(RncePrivKey, RncePubKey)] = Try {
      RnceBatchedEncryption.keygen(params)
    }
}
