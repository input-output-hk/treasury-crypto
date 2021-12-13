package io.iohk.protocol

import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.core.utils.HasSize
import io.iohk.protocol.keygen.datastructures.round1.{R1Data, SecretShare}
import io.iohk.protocol.keygen.datastructures.round2.R2Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.{OpenedShare, R4Data}
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2Data

import scala.collection.mutable.ArrayBuffer

package object keygen {

  case class IntAccumulator(var value: Int = 0){
    def plus(i: Int): Int = {value += i; value}
  }

  case class CRS_commitment (issuerID: Int, crs_commitment: Array[GroupElement])
  case class Commitment     (issuerID: Int, commitment: Array[GroupElement])
  case class Share          (issuerID: Int, share_a: OpenedShare, share_b: OpenedShare)
  case class ShareEncrypted (issuerID: Int, share_a: SecretShare, share_b: SecretShare)

  case class ViolatorShare(violatorID: Int, violatorShares: ArrayBuffer[Share])

  type SharedPublicKey = Array[Byte]

  //----------------------------------------------------------
  // Data structures for setting state
  //

  case class RoundsData(
     var r1Data: Seq[R1Data] = Seq(),
     var r2Data: Seq[R2Data] = Seq(),
     var r3Data: Seq[R3Data] = Seq(),
     var r4Data: Seq[R4Data] = Seq(),
     var r5_1Data: Seq[R5_1Data] = Seq(),
     var r5_2Data: Seq[R5_2Data] = Seq()
  )

  //----------------------------------------------------------
  // Tally decryption data structures
  //

  case class SKShare(
    ownerID: Int,
    share:   BigInt
  ) extends HasSize {

    def size: Int = {
      4 + share.toByteArray.size
    }
  }

  case class KeyShares(
    issuerID:    Int,
    keyShares:   Seq[SKShare]
  ) extends HasSize {

    def size: Int = {
      4 + keyShares.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }
}
