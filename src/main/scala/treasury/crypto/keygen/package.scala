package treasury.crypto

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints}
import treasury.crypto.core._
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.nizk.ElgamalDecrNIZKProof

import scala.util.{Random, Try}

package object keygen {

  case class IntAccumulator(var value: Int = 0){
    def plus(i: Int): Int = {value += i; value}
  }

  //----------------------------------------------------------
  // Round 1 data structures
  //
  case class SecretShare(receiverID: Integer, S: HybridCiphertext)
    extends HasSize with BytesSerializable {

    override type M = SecretShare
    override val serializer: Serializer[M] = SecretShareSerializer

    def size: Int = bytes.length
  }

  object SecretShareSerializer extends Serializer[SecretShare] {

    override def toBytes(obj: SecretShare): Array[Byte] = {

      val S_bytes = obj.S.bytes

      Bytes.concat(
        Ints.toByteArray(obj.receiverID),
        Ints.toByteArray(S_bytes.length),
        S_bytes
      )
    }

    override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[SecretShare] = Try {

      val offset = IntAccumulator(0)

      val receiverID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

      val S_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
      val S_bytes = bytes.slice(offset.value, offset.plus(S_bytes_len))

      val S = HybridCiphertextSerializer.parseBytes(S_bytes, cs)

      SecretShare(receiverID, S.get)
    }
  }

  case class OpenedShare(receiverID: Integer, S: HybridPlaintext)
    extends HasSize {

    def size: Int = bytes.length

    def bytes: Array[Byte] = {
      Bytes.concat(
        Ints.toByteArray(receiverID),
        Ints.toByteArray(S.size),
        S.bytes
      )
    }
  }

  case class R1Data(
    issuerID: Integer,            // ID of commitments and shares issuer
    E:        Array[Array[Byte]], // CRS commitments for coefficients of the both polynomials (E = g * a_i + h * b_i; i = [0; t) )
    S_a:      Array[SecretShare], // poly_a shares for each of k = n-1 committee members
    S_b:      Array[SecretShare]  // poly_b shares for each of k = n-1 committee members
  ) extends HasSize with BytesSerializable {

    override type M = R1Data
    override val serializer: Serializer[M] = R1DataSerializer

    def size: Int = bytes.length

    def canEqual(a: Any): Boolean = a.isInstanceOf[R1Data]

    override def equals(that: Any): Boolean =
      that match {
        case that: R1Data => that.canEqual(this) && this.hashCode == that.hashCode
        case _ => false
      }

    override def hashCode: Int = {

      import java.util.zip.CRC32

      val checksum = new CRC32
      checksum.update(bytes, 0, bytes.length)
      checksum.getValue.toInt
    }
  }

  object R1DataSerializer extends Serializer[R1Data] {

    override def toBytes(obj: R1Data): Array[Byte] = {

      val E_bytes   = obj.E.foldLeft(Array[Byte]())  {(acc, e) => acc ++ Ints.toByteArray(e.length) ++ e}
      val S_a_bytes = obj.S_a.foldLeft(Array[Byte]()){(acc, s) => acc ++ Ints.toByteArray(s.size) ++ s.bytes}
      val S_b_bytes = obj.S_b.foldLeft(Array[Byte]()){(acc, s) => acc ++ Ints.toByteArray(s.size) ++ s.bytes}

      Bytes.concat(
        Ints.toByteArray(obj.issuerID),
        Ints.toByteArray(obj.E.length),
        E_bytes,
        Ints.toByteArray(obj.S_a.length),
        S_a_bytes,
        Ints.toByteArray(obj.S_b.length),
        S_b_bytes
      )
    }

    override def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[R1Data] = Try {

      val offset = IntAccumulator(0)

      val issuerID = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

      val E_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

      val E = for (_ <- 0 until E_len) yield {
          val e_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
          bytes.slice(offset.value, offset.plus(e_len))
      }

      val S_a_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

      val S_a = for (_ <- 0 until S_a_len) yield {
          val S_a_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
          val S_a_bytes = bytes.slice(offset.value, offset.plus(S_a_bytes_len))
          SecretShareSerializer.parseBytes(S_a_bytes, cs).get
      }

      val S_b_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))

      val S_b = for (_ <- 0 until S_b_len) yield {
          val S_b_bytes_len = Ints.fromByteArray(bytes.slice(offset.value, offset.plus(4)))
          val S_b_bytes = bytes.slice(offset.value, offset.plus(S_b_bytes_len))
          SecretShareSerializer.parseBytes(S_b_bytes, cs).get
      }

      R1Data(issuerID, E.toArray, S_a.toArray, S_b.toArray)
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
