package io.iohk.protocol.keygen_him.NIZKs.CorrectDecryptionNIZK

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.core.crypto.primitives.hash.{CryptographicHash, CryptographicHashFactory}
import io.iohk.protocol.common.dlog_encryption.DLogCiphertext
import io.iohk.protocol.common.encoding.BaseCodec
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{div, evaluateLiftedPoly, exp}
import io.iohk.protocol.keygen_him.NIZKs.CorrectDecryptionNIZK.CorrectDecryption.{Statement, Witness}
import io.iohk.protocol.keygen_him.NIZKs.CorrectDecryptionNIZK.datastructures.Proof
import io.iohk.protocol.nizk.DLEQStandardNIZK

case class CorrectDecryption(statement: Statement)
                            (implicit dlogGroup: DiscreteLogGroup){
  implicit private val hashFunction: CryptographicHash =
    CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  private val D1 = evaluateLiftedPoly(statement.ciphertext.C.map(_.c1), BaseCodec.defaultBase)
  private val D2 = evaluateLiftedPoly(statement.ciphertext.C.map(_.c2), BaseCodec.defaultBase)

  private val G1 = dlogGroup.groupGenerator
  private val H1 = statement.pubKey
  private val G2 = D1
  private val H2 = div(D2, exp(G1, statement.plaintext))

  def prove(witness: Witness)
           (implicit dlogGroup: DiscreteLogGroup): Proof = {
    Proof( // G1^sk = H1 && G2^sk = H2
      DLEQStandardNIZK.produceNIZK(H1, H2, G1, G2, witness.sk).get
    )
  }

  def verify(proof: Proof): Boolean = {
    DLEQStandardNIZK.verifyNIZK(H1, H2, G1, G2, proof.dlEqProof)
  }
}

object CorrectDecryption{
  case class Statement(pubKey: GroupElement, plaintext: BigInt, ciphertext: DLogCiphertext)
  case class Witness(sk: BigInt) // secret key
}
