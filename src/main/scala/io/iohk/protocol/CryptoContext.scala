package io.iohk.protocol

import io.iohk.core.crypto.primitives.blockcipher.{BlockCipher, BlockCipherFactory}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory, GroupElement}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.{CryptographicHash, CryptographicHashFactory}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes

/**
  * CryptoContext holds instantiations of cryptographic primitives that are used by throughout the protocol and
  * some other common parameters.
  * CryptoContext is usually passed as a parameter to all other components. It is supposed to be
  * a singleton for the platform where the treasury-crypto is integrated.
  *
  * Note that crsIn should be a valid group element of the groupIn. It serves as a common reference string for some
  * parts of the protocol and, thus, should be securely generated as crs = G.pow(sk), where G is a group generator and sk is a
  * secret key that was destroyed after calculating crs. So this implies either trusted setup or some setup ceremony for
  * crs derivation. How exactly crs is generated is outside the scope of this library.
  *
  * @param crsIn common reference string. In case None, a random group element will be generated.
  * @param groupIn discrete logarithm group. In case None is passed a default group will be created.
  * @param hashIn cryptographic hash. In case None is passed a default hash function will be used.
  * @param blockCipherIn block cipher. In case None is Passed a default block cipher will be used.
  */
class CryptoContext(crsIn: Option[GroupElement],
                    groupIn: Option[DiscreteLogGroup] = None,
                    hashIn: Option[CryptographicHash] = None,
                    blockCipherIn: Option[BlockCipher] = None) {

  implicit val group = groupIn.getOrElse(CryptoContext.defaultGroup)
  implicit val hash = hashIn.getOrElse(CryptoContext.defaultHash)
  implicit val blockCipher = blockCipherIn.getOrElse(CryptoContext.defaultBlockCipher)

  crsIn.foreach(crs => require(group.isValidGroupElement(crs)))
  val commonReferenceString: GroupElement = crsIn.getOrElse(group.createRandomGroupElement.get)
}

object CryptoContext {

  lazy val defaultGroup = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  lazy val defaultHash = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get
  lazy val defaultBlockCipher = BlockCipherFactory.constructBlockCipher(AvailableBlockCiphers.AES128_BSM_Bc).get

  /**
    * This method is only for testing purposes. In a production mode, CRS value should be securely generated
    * outside of the library
    * @param group
    * @return random group element
    */
  def generateRandomCRS(implicit group: DiscreteLogGroup = defaultGroup) = {
    group.groupGenerator.pow(group.createRandomNumber).get
  }
}