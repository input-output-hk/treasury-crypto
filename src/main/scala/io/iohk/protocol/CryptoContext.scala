package io.iohk.protocol

import io.iohk.core.crypto.primitives.blockcipher.{BlockCipher, BlockCipherFactory}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.{CryptographicHash, CryptographicHashFactory}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes

/*
 * CryptoContext holds instantiations of cryptographic primitives that are used by the voting protocol.
 * Note that it can be used with default values, in this case nothing should be passed to the constructor, all needed
 * primitives will be created internally.
 * CryptoContext is usually passed as a parameter to all other components of the voting protocol. It is supposed to be
 * a singleton for the platform where the treasury-crypto is integrated.
 */
class CryptoContext(groupIn: Option[DiscreteLogGroup] = None,
                    hashIn: Option[CryptographicHash] = None,
                    blockCipherIn: Option[BlockCipher] = None) {

  implicit val group = groupIn.getOrElse {
    DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  }
  implicit val hash = hashIn.getOrElse{
    CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  }
  implicit val blockCipher = blockCipherIn.getOrElse{
    BlockCipherFactory.constructBlockCipher(AvailableBlockCiphers.AES128_BSM_Bc).get
  }
}
