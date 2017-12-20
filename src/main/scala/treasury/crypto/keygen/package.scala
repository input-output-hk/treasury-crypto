package treasury.crypto

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.nizk.ElgamalDecrNIZK.ElgamalDecrNIZKProof

import scala.util.Random

package object keygen {

  //----------------------------------------------------------
  // Round 1 data structures
  //
  case class SecretShare(receiverID: Integer, S: HybridCiphertext) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      S.size
    }
  }

  case class OpenedShare(receiverID: Integer, S: HybridPlaintext) extends HasSize {
    def size: Int = {
      Integer.BYTES +
      S.size
    }
  }

  case class R1Data(
    issuerID: Integer,            // ID of commitments and shares issuer
    E:        Array[Array[Byte]], // CRS commitments for coefficients of the both polynomials (E = g * a_i + h * b_i; i = [0; t) )
    S_a:      Array[SecretShare], // poly_a shares for each of k = n-1 committee members
    S_b:      Array[SecretShare] // poly_b shares for each of k = n-1 committee members
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      E.foldLeft(0)   {(totalSize, currentElement) => totalSize + currentElement.length} +
      S_a.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size} +
      S_b.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }

  //----------------------------------------------------------
  // Round 2 data structures
  //
  case class ShareProof(
    encryptedShare:  HybridCiphertext,
    decryptedShare:  HybridPlaintext,
    NIZKProof:       ElgamalDecrNIZKProof
  ) extends HasSize {

    def size: Int = {
      encryptedShare.size +
      decryptedShare.size +
      NIZKProof.size
    }
  }

  case class ComplaintR2(
    violatorID:        Integer,
    issuerPublicKey:   PubKey,
    shareProof_a:      ShareProof,
    shareProof_b:      ShareProof
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      issuerPublicKey.getEncoded(true).size +
      shareProof_a.size +
      shareProof_b.size
    }
  }

  case class R2Data(complaints: Array[ComplaintR2]) extends HasSize {
    def size: Int = {
      complaints.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }

  //----------------------------------------------------------
  // Round 3 data structures
  //
  case class R3Data(
    issuerID:    Integer,
    commitments: Array[Array[Byte]]
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      commitments.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }

  //----------------------------------------------------------
  // Round 4 data structures
  //
  case class ComplaintR4(
    violatorID:  Integer,
    share_a:     OpenedShare,
    share_b:     OpenedShare
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      share_a.size +
      share_b.size
    }
  }

  case class R4Data(
    issuerID:    Integer,
    complaints:  Array[ComplaintR4]
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      complaints.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }

  //----------------------------------------------------------
  // Round 5.1 data structures
  //
  case class R5_1Data(
    issuerID:        Integer,
    violatorsShares: Array[(Integer, OpenedShare)] // decrypted share from violator to issuer of this message
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      violatorsShares.foldLeft(0) {(totalSize, currentElement) => totalSize + (Integer.BYTES + currentElement._2.size)}
    }
  }
  //----------------------------------------------------------
  // Round 5.2 data structures
  //
  type SharedPublicKey = Array[Byte]

  case class SecretKey(
    ownerID:   Integer,
    secretKey: Array[Byte]
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      secretKey.size
    }
  }
  case class R5_2Data(
    sharedPublicKey:     SharedPublicKey,
    violatorsSecretKeys: Array[SecretKey]
  ) extends HasSize {

    def size: Int = {
      sharedPublicKey.length +
      violatorsSecretKeys.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }

  //----------------------------------------------------------
  // Tally decryption data structures
  //
  case class C1(
    issuerID:           Integer,
    issuerPubKey:       PubKey,
    decryptedC1:        Seq[Point],
    decryptedC1Proofs:  Seq[ElgamalDecrNIZKProof]
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      issuerPubKey.getEncoded(true).size +
      decryptedC1.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.getEncoded(true).size} +
      decryptedC1Proofs.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }

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
        r3DataPatched(i).commitments(0) = cs.infinityPoint.getEncoded(true)

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
