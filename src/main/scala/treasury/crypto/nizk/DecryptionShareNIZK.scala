package treasury.crypto.nizk

import java.math.BigInteger

import treasury.crypto.core.encryption.encryption.{PrivKey, PubKey}
import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, GroupElement}
import treasury.crypto.core.primitives.hash.CryptographicHash

import scala.util.Try

/* This is a version of the Decryption Share NIZK based on the new crypto core layer */
object DecryptionShareNIZK {

  case class DecryptionShareNIZKProof(A1: GroupElement, A2: GroupElement, z: BigInt)

  def produceNIZK(share: GroupElement, privKey: PrivKey)
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[DecryptionShareNIZKProof] = Try {

    val w = dlogGroup.createRandomNumber
    val G = dlogGroup.groupGenerator
    val A1 = dlogGroup.exponentiate(G, w).get
    val A2 = dlogGroup.exponentiate(share, w).get
    val D = dlogGroup.exponentiate(share, privKey).get

    val e = new BigInteger(
      hashFunction.hash {
        share.bytes ++
          D.bytes ++
          A1.bytes ++
          A2.bytes
      }).mod(dlogGroup.groupOrder)

    val z = (privKey * e + w) mod dlogGroup.groupOrder

    DecryptionShareNIZKProof(A1, A2, z)
  }

  def verifyNIZK(pubKey: PubKey, share: GroupElement, decryptedShare: GroupElement, proof: DecryptionShareNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = {

    val e = new BigInteger(
      hashFunction.hash {
        share.bytes ++
        decryptedShare.bytes ++
        proof.A1.bytes ++
        proof.A2.bytes
      }).mod(dlogGroup.groupOrder)

    val G = dlogGroup.groupGenerator
    val Gz = dlogGroup.exponentiate(G, proof.z).get
    val He = dlogGroup.exponentiate(pubKey, e).get
    val HeA1 = dlogGroup.multiply(He, proof.A1).get

    val C1z = dlogGroup.exponentiate(share, proof.z).get
    val De = dlogGroup.exponentiate(decryptedShare, e).get
    val DeA2 = dlogGroup.multiply(De, proof.A2).get

    Gz.equals(HeA1) && C1z.equals(DeA2)
  }
}
