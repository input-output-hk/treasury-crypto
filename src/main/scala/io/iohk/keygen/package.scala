package io.iohk

import java.math.BigInteger

import io.iohk.core.Cryptosystem
import io.iohk.keygen.datastructures.round1.SecretShare
import io.iohk.keygen.datastructures.round2.R2Data
import io.iohk.keygen.datastructures.round3.R3Data
import io.iohk.keygen.datastructures.round4.{OpenedShare, R4Data}
import io.iohk.keygen.datastructures.round5_2.R5_2Data
import io.iohk.core._
import io.iohk.keygen.datastructures.round1.{R1Data, SecretShare}
import io.iohk.keygen.datastructures.round2.R2Data
import io.iohk.keygen.datastructures.round3.R3Data
import io.iohk.keygen.datastructures.round4.{OpenedShare, R4Data}
import io.iohk.keygen.datastructures.round5_1.R5_1Data
import io.iohk.keygen.datastructures.round5_2.R5_2Data

import scala.collection.mutable.ArrayBuffer
import scala.util.Random

package object keygen {

  case class IntAccumulator(var value: Int = 0){
    def plus(i: Int): Int = {value += i; value}
  }

  case class CRS_commitment (issuerID: Integer, crs_commitment: Array[Point])
  case class Commitment     (issuerID: Integer, commitment: Array[Point])
  case class Share          (issuerID: Integer, share_a: OpenedShare, share_b: OpenedShare)
  case class ShareEncrypted (issuerID: Integer, share_a: SecretShare, share_b: SecretShare)

  case class ViolatorShare(violatorID: Integer, violatorShares: ArrayBuffer[OpenedShare])

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
    ownerID: Integer,
    share:   BigInteger
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      share.toByteArray.size
    }
  }

  case class KeyShares(
    issuerID:    Integer,
    keyShares:   Seq[SKShare]
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      keyShares.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }

  //----------------------------------------------------------
  // For testing purposes
  //
  def patchR3Data(cs: Cryptosystem, r3Data: Seq[R3Data], numOfPatches: Int): Seq[R3Data] = {
    require(numOfPatches <= r3Data.length)

    var r3DataPatched = r3Data

    var indexesToPatch = Array.fill[Boolean](numOfPatches)(true) ++ Array.fill[Boolean](r3Data.length - numOfPatches)(false)
    indexesToPatch = Random.shuffle(indexesToPatch.toSeq).toArray

    for(i <- r3Data.indices)
      if(indexesToPatch(i))
        r3DataPatched(i).commitments(0) = cs.infinityPoint.bytes

    r3DataPatched
  }

  def getSharedPublicKey(cs: Cryptosystem, committeeMembers: Seq[CommitteeMember]): PubKey = {
    val r1Data    = committeeMembers.map(_.setKeyR1   ())
    val r2Data    = committeeMembers.map(_.setKeyR2   (r1Data))
    val r3Data    = committeeMembers.map(_.setKeyR3   (r2Data))

    val r3DataPatched = patchR3Data(cs, r3Data, 1)
//    val r3DataPatched = r3Data

    val r4Data    = committeeMembers.map(_.setKeyR4   (r3DataPatched))
    val r5_1Data  = committeeMembers.map(_.setKeyR5_1 (r4Data))
    val r5_2Data  = committeeMembers.map(_.setKeyR5_2 (r5_1Data))

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(cs.decodePoint)

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys.head)))
    sharedPublicKeys.head
  }
}
