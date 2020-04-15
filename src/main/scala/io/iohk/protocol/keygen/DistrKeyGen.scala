package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.core.crypto.primitives.numbergenerator.{FieldElementSP800DRNG, SP800DRNG}
import io.iohk.protocol.keygen.DistrKeyGen.{checkCommitmentR3, checkComplaintR2, checkOnCRS}
import io.iohk.protocol.keygen.datastructures.round1.{R1Data, SecretShare}
import io.iohk.protocol.keygen.datastructures.round2.{ComplaintR2, R2Data, ShareProof}
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.{ComplaintR4, OpenedShare, R4Data}
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.{R5_2Data, SecretKey}
import io.iohk.protocol.keygen.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

/**
  *   DistrKeyGen encapsulates the logic of generating a shared public key that will be used to encrypt voters ballots.
  * It is used by committee members to perform their duties and by all other entities to verify messages from committee members.
  * Each committee member creates an instance of DistrKeyGen, which is set up with his own keys.
  *   According to the protocol each committee member has two pairs of keys, the one is used for generating a shared public key
  * and another one is used for sending encrypted messages among committee members.
  *   The distributed key generation protocol consists of 5 rounds executing sequentially. At each round a committee member is
  * supposed to create and publish certain messages based on what was an outcome of the previous round. After executing each
  * round the internal state of the DistrKeyGen is updated.
  *
  * @param ctx  CryptoContext
  * @param transportKeyPair a key pair for ElGamal encryption scheme that is used for encrypted communication among committee members.
  *                         The transport public key serves also as an identifier of a committee member.
  * @param secretKey a secret key for ElGamal encryption scheme that is used for generating shared public key
  * @param secretSeed a secret seed used to generate random values required for certain parts of the protocol (Note that
  *                   in some cases, it might be plausible to derive the seed from the transport secret key. It is not
  *                   recommended to derive the seed from the secretKey, as it is not guaranteed to be safe according to the
  *                   current security model)
  * @param membersPubKeys An array of transport public keys of all committee members participating in the DKG protocol
  *                       (including own transport public key from transportKeyPair)
  * @param memberIdentifier an instance of Identifier, that deterministically maps a set of committee transport public keys
  *                         to integer indices [0,...,n-1], where n is the number of keys in the set. Note that it should be
  *                         correctly preloaded with keys from membersPublicKeys.
  * @param roundsData contains outcomes of DKG rounds that have been already executed (by an outcome of a round means a set
  *                   of messages from all committee members generated during this round). It is needed to be able to restore
  *                   the state to a certain point (e.g., if we already have outcomes of Rounds 1 and 2, we set up
  *                   the DistrKeyGen with this data, so that it can continue with Round 3 immediately)
  *
  */
class DistrKeyGen(ctx:              CryptoContext,
                  transportKeyPair: KeyPair,
                  secretKey:        PrivKey,
                  secretSeed:       Array[Byte],
                  membersPubKeys:   Seq[PubKey],
                  memberIdentifier: Identifier[Int],
                  roundsData:       RoundsData)
{
  import ctx.{blockCipher, group, hash}

  private val CRS_commitments = new ArrayBuffer[CRS_commitment]() // CRS commitments of other participants
  private val commitments     = new ArrayBuffer[Commitment]()     // Commitments of other participants
  private val shares          = new ArrayBuffer[Share]()          // Shares(decrypted) of other participants
  private val secretShares    = new ArrayBuffer[ShareEncrypted]() // Secret(encrypted) shares of other participants
  private val violatorsIDs    = new ArrayBuffer[Int]()        // ID's of members-violators (absent on the 1-st round, and those, who supplied incorrect commitments on rounds 1 and 3)
  private val absenteesIDs    = new ArrayBuffer[Int]()        // ID's of members who were absent on round 3, so their secrets should be reconstructed

  private val n = membersPubKeys.size           // Total number of protocol participants
          val t = (n.toFloat / 2).ceil.toInt    // Threshold number of participants
  private val A = new Array[GroupElement](t)         // Own commitments

  private val crs = ctx.commonReferenceString.get
  private val g = group.groupGenerator

  private val ownTransportPrivateKey = transportKeyPair._1
  private val ownTransportPublicKey  = transportKeyPair._2
  private val allMembersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
          val ownID: Int = memberIdentifier.getId(ownTransportPublicKey).get

          val roundsDataCache = RoundsData()
  private var roundsPassed: Int = 0
  def getRoundsPassed: Int = roundsPassed

  if (initialize(roundsData).isFailure) throw new Exception("Wasn't initialized!")

  def getShare(id: Int): Option[BigInt] = {

    val shareOpt = shares.find(_.issuerID == id)
    shareOpt match {
      case Some(share) => Some(BigInt(share.share_a.S.decryptedMessage))
      case None => None
    }
  }

  /**
    * Executes the 1-st round of the DKG protocol.
    *
    * Generates random polynomials, CRS commitments for both of them and secret shares for the 0-th coefficient of the each polynomial.
    * In the first polynomial (poly_a) the 0-th coefficient is the supplied secret key.
    *
    * Generated data is placed into the R1Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR1Data) is supplied, the check for identity of generated R1Data and prevR1Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR1Data and newly generated R1Data are inconsistent and None is returned, the generated R1Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R1Data from the first method execution will be returned.
    * If this method is called when it should not be, by the protocol order, then None will be returned.
    *
    * @param prevR1Data optional, R1data from previous execution of this round (should be passed during internal state restoration)
    * @return Some(R1Data) if success, None otherwise
    */
  def doRound1(prevR1Data: Option[R1Data] = None): Option[R1Data] = {

    roundsPassed match {
      case 1 => return roundsDataCache.r1Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 0) => return None // Round should be executed strictly after the previous round
      case 0 =>
    }

    // we set a_0 to be the secretKey and generate all other coefficients with an RNG seeded with secretSeed
    val drng = new FieldElementSP800DRNG(secretSeed ++ "Polynomials".getBytes, ctx.group.groupOrder)
    val poly_a = new Polynomial(ctx, t, secretKey, drng)
    val poly_b = new Polynomial(ctx, t, drng.nextRand, drng)

    for(i <- A.indices)
      A(i) = g.pow(poly_a(i)).get

    val E   = new ArrayBuffer[Array[Byte]]()
    val S_a = new ArrayBuffer[SecretShare]()
    val S_b = new ArrayBuffer[SecretShare]()

    // CRS commitments for each coefficient of both polynomials
    for(i <- A.indices)
      E += A(i).multiply(crs.pow(poly_b(i))).get.bytes

    for(i <- membersPubKeys.indices)
    {
      val receiverPublicKey = membersPubKeys(i)

      if(receiverPublicKey != ownTransportPublicKey)
      {
        val recipientID = memberIdentifier.getId(receiverPublicKey).get
        val x = recipientID + 1

        assert(x != 0) // avoid share for a_0 coefficient

        val seed = secretSeed ++ BigInt(x).toByteArray ++ receiverPublicKey.bytes ++ "SecretSharesSeed".getBytes //TODO: verify if it is secure to use this seed
        val gen = new SP800DRNG(seed)
        S_a += SecretShare(recipientID, HybridEncryption.encrypt(receiverPublicKey, poly_a.evaluate(x).toByteArray, gen.nextBytes(32)).get)
        S_b += SecretShare(recipientID, HybridEncryption.encrypt(receiverPublicKey, poly_b.evaluate(x).toByteArray, gen.nextBytes(32)).get)
      }
    }
    val r1Data = R1Data(ownID, E.toArray, S_a.sortBy(_.receiverID).toArray, S_b.sortBy(_.receiverID).toArray)

    roundsPassed += 1
    roundsDataCache.r1Data = Seq(r1Data) // round output is always cached

    // Check if the current round output is equal to data from previous execution
    // If not - the current round output can be taken from cache
    prevR1Data match {
      case Some(data) =>
        val prevR1DataSorted = R1Data(data.issuerID, data.E, data.S_a.sortBy(_.receiverID), data.S_b.sortBy(_.receiverID))
        prevR1DataSorted match {
          case prevData if !prevData.equals(r1Data) => None
          case _ => Some(r1Data)
        }
      case None => Some(r1Data)
    }
  }

  /**
    * Executes the 2-nd round of the DKG protocol.
    *
    * Verifies 1-st round CRS commitments supplied by other members (placed in R1Data) and creates complaints on those of them, who's data is incorrect.
    * The members, who have supplied incorrect 1-st round commitments, are listed as violators and will be ignored during the further protocol execution.
    * The members, who haven't supplied any commitments at all, are also listed as violators.
    *
    * Created complaints (if any) are placed into the R2Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR2Data) is supplied, the check for identity of generated R2Data and prevR2Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR2Data and newly generated R2Data are inconsistent and None is returned, the generated R2Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R2Data from the first method execution will be returned.
    * If this method is called in wrong order, None is returned.
    *
    * @param r1Data a sequence of R1Data packets of all protocol members (including the own one)
    * @param prevR2Data optional, R2data from a previous execution of this round (should be passed during internal state restoring)
    * @return Some(R2Data) if success, None otherwise
    */
  def doRound2(r1Data: Seq[R1Data], prevR2Data: Option[R2Data] = None): Option[R2Data] = {

    roundsPassed match {
      case 2 => return roundsDataCache.r2Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 1) => return None // Round should be executed strictly after the previous round
      case 1 =>
    }

    var complaints = new ArrayBuffer[ComplaintR2]()

    for(i <- r1Data.indices) {
      assert(r1Data(i).S_a.length == r1Data(i).S_b.length)

      for(j <- r1Data(i).S_a.indices) {
        if(r1Data(i).S_a(j).receiverID == ownID) {
          val secretShare_a = r1Data(i).S_a(j)
          val secretShare_b = r1Data(i).S_b(j)

          val openedShare_a = OpenedShare(secretShare_a.receiverID, HybridEncryption.decrypt(ownTransportPrivateKey, secretShare_a.S).get)
          val openedShare_b = OpenedShare(secretShare_b.receiverID, HybridEncryption.decrypt(ownTransportPrivateKey, secretShare_b.S).get)

          if(checkOnCRS(ctx, openedShare_a, openedShare_b, r1Data(i).E)) {
            secretShares += ShareEncrypted(r1Data(i).issuerID, secretShare_a, secretShare_b)
            shares += Share(r1Data(i).issuerID, openedShare_a, openedShare_b)
            CRS_commitments += CRS_commitment(r1Data(i).issuerID, r1Data(i).E.map(x => group.reconstructGroupElement(x).get))
          }
          else {
            val proof_a = ElgamalDecrNIZK.produceNIZK(secretShare_a.S.encryptedSymmetricKey, ownTransportPrivateKey).get
            val proof_b = ElgamalDecrNIZK.produceNIZK(secretShare_b.S.encryptedSymmetricKey, ownTransportPrivateKey).get

            complaints += ComplaintR2(
              r1Data(i).issuerID,
              ownTransportPublicKey,
              ShareProof(secretShare_a.S, openedShare_a.S, proof_a),
              ShareProof(secretShare_b.S, openedShare_b.S, proof_b))

            violatorsIDs += r1Data(i).issuerID
          }
        }
      }
    }

    // Avoid participation of absent members in further rounds
    val activeMembers = r1Data.map(_.issuerID)
    val absentMembers = allMembersIDs.diff(activeMembers)
    absentMembers.foreach(x => violatorsIDs += x)

    // Sort complaints array for ability to compare R2Data to each other
    val r2Data = R2Data(ownID, complaints.sortBy(_.violatorID).toArray)

    roundsPassed += 1
    roundsDataCache.r2Data = Seq(r2Data) // round output is always cached

    prevR2Data match {
      case Some(data) =>
        val prevR2DataSorted = R2Data(data.issuerID, data.complaints.sortBy(_.violatorID))
        prevR2DataSorted match {
          case prevData if !prevData.equals(r2Data) => None
          case _ => Some(r2Data)
        }
      case None => Some(r2Data)
    }
  }

  /**
    * Executes the 3-rd round of the DKG protocol.
    *
    * Checks complaints from non-disqualified members, contained in r2DataIn.
    * In case of at least one valid complaint, the corresponding member is listed as a protocol violator and his shares and commitments from the round 1 are deleted. Such a member will be ignored during the further protocol execution.
    * Posts own commitments of the poly_a coefficients (commitments are placed into the R3Data structure).
    *
    * The R3Data structure should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR3Data) is supplied, the check for identity of generated R3Data and prevR3Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR3Data and newly generated R3Data are inconsistent and None is returned, the generated R3Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R3Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r2DataIn a sequence of R2Data packets of all protocol members (including the own one).
    * @param prevR3Data optional, R3data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R3Data) if success, None otherwise
    */
  def doRound3(r2DataIn: Seq[R2Data], prevR3Data: Option[R3Data] = None): Option[R3Data] = {
    def checkComplaint(complaint: ComplaintR2): Boolean = {
      def checkProof(pubKey: PubKey, proof: ShareProof): Boolean = {
        ElgamalDecrNIZK.verifyNIZK(
          pubKey,
          proof.encryptedShare.encryptedSymmetricKey,
          proof.decryptedShare.decryptedKey,
          proof.NIZKProof)
      }

      def checkEncryption(proof: ShareProof): Boolean = {
        val ciphertext = HybridEncryption.encrypt(
          ownTransportPublicKey,                         // for this verification no matter what public key is used
          proof.decryptedShare.decryptedMessage,
          proof.decryptedShare.decryptedKey).get

        ciphertext.encryptedMessage.equals(proof.encryptedShare.encryptedMessage)
      }

      val publicKey = complaint.issuerPublicKey
      val proof_a = complaint.shareProof_a
      val proof_b = complaint.shareProof_b

      (checkProof(publicKey, proof_a) && checkEncryption(proof_a)) &&
      (checkProof(publicKey, proof_b) && checkEncryption(proof_b))
    }

    roundsPassed match {
      case 3 => return roundsDataCache.r3Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 2) => return None // Round should be executed strictly after the previous round
      case 2 =>
    }

    // Ignore messages from disqualified members
    val r2Data = r2DataIn.filter(x => !violatorsIDs.contains(x.issuerID))

    // Remove received shares and commitments of disqualified members (if they were verified successfully, but at least 1 complaint on their issuer was received)
    for(i <- r2Data.indices) {
      for(j <- r2Data(i).complaints.indices) {
        val complaint = r2Data(i).complaints(j)
        val violatorID = complaint.violatorID

        val violatorsCRSCommitment = CRS_commitments.find(_.issuerID == violatorID)
        val violatorsSecretShare = secretShares.find(_.issuerID == violatorID)

        if(violatorID != ownID &&
           violatorsCRSCommitment.isDefined &&
           violatorsSecretShare.isDefined &&
           checkComplaintR2(
             ctx,
             complaint,
             violatorsSecretShare.get,
             memberIdentifier,
             violatorsCRSCommitment.get.crs_commitment.map(_.bytes))) {

          CRS_commitments -= violatorsCRSCommitment.get
          secretShares -= violatorsSecretShare.get

          val violatorShare = shares.find(_.issuerID == violatorID)
          if(violatorShare.isDefined)
            shares -= violatorShare.get

          if(!violatorsIDs.contains(violatorID))
            violatorsIDs += violatorID
        }
      }
    }

    // Commitments of poly_a coefficients
    val r3Data = R3Data(ownID, A.map(_.bytes))

    roundsPassed += 1
    roundsDataCache.r3Data = Seq(r3Data) // round output is always cached

    prevR3Data match {
      case Some(data) =>
        data match {
          case prevData if !prevData.equals(r3Data) => None
          case _ => Some(r3Data)
        }
      case None => Some(r3Data)
    }
  }

  def checkCommitment(issuerID: Int, commitment: Array[Array[Byte]]): Boolean = {

    val A = commitment.map(group.reconstructGroupElement(_).get)
    var A_sum: GroupElement = group.groupIdentity
    val share = shares.find(_.issuerID == issuerID)
    if(share.isDefined) {
      val X = BigInt(share.get.share_a.receiverID.toLong + 1)

      for(i <- A.indices) {
        A_sum = A_sum.multiply(A(i).pow(X.pow(i)).get).get
      }

      val share_a = BigInt(share.get.share_a.S.decryptedMessage)
      val g_sa = g.pow(share_a)

      g_sa.equals(A_sum)
    }
    else // commitment belongs to the disqualified member
      false
  }

  /**
    * Executes the 4-th round of the DKG protocol.
    *
    * Verifies 3-rd round commitments supplied by other members (placed in R3Data) and creates complaints on those of them, who's data is incorrect.
    * The members, who has supplied incorrect 3-rd round commitments, are listed as violators and will be ignored during the further protocol execution.
    * The members, who hasn't supplied any 3-rd round commitments, are listed as absentees, and their secret keys will be reconstructed during rounds 5_1, 5_2. Absentees will also be ignored during the further protocol execution.
    *
    * Created complaints (if any) are placed into the R4Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR4Data) is supplied, the check for identity of generated R4Data and prevR4Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR4Data and newly generated R4Data are inconsistent and None is returned, the generated R4Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R4Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r3DataIn a sequence of R3Data packets of all protocol members (including the own one).
    * @param prevR4Data optional, R4Data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R4Data) if success, None otherwise
    */
  def doRound4(r3DataIn: Seq[R3Data], prevR4Data: Option[R4Data] = None): Option[R4Data] = {

    roundsPassed match {
      case 4 => return roundsDataCache.r4Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 3) => return None // Round should be executed strictly after the previous round
      case 3 =>
    }

    // Ignore messages from disqualified members
    val r3Data = r3DataIn.filter(x => !violatorsIDs.contains(x.issuerID))

    var complaints = new ArrayBuffer[ComplaintR4]()

    for(i <- r3Data.indices) {
      val issuerID = r3Data(i).issuerID
      val issuerCommitments = r3Data(i).commitments

      if(issuerID != ownID) {

        val share = shares.find(_.issuerID == issuerID)
        if(share.isDefined) {

          if(checkCommitmentR3(ctx, share.get, issuerCommitments)) {
            commitments += Commitment(issuerID, issuerCommitments.map(group.reconstructGroupElement(_).get))
          } else {
            complaints += ComplaintR4(issuerID, share.get.share_a, share.get.share_b)
            violatorsIDs += issuerID
          }
        } //if(!share.isDefined) is the case, when a member is disqualified, and his shares are already deleted from the local state of the current member
      }
    }

    // Members, who hasn't supplied 3-rd round data, are absentees, who's secret keys should be restored for ability to get their individual public key
    val activeMembers = r3Data.map(_.issuerID)
    val absentMembers = allMembersIDs.diff(activeMembers) // violators and absentees
    absentMembers.foreach(id => if(!violatorsIDs.contains(id)) absenteesIDs += id)

    val r4Data = R4Data(ownID, complaints.sortBy(_.violatorID).toArray)

    roundsPassed += 1
    roundsDataCache.r4Data = Seq(r4Data) // round output is always cached

    prevR4Data match {
      case Some(data) =>
        val prevR4DataSorted = R4Data(data.issuerID, data.complaints.sortBy(_.violatorID))
        prevR4DataSorted match {
          case prevData if !prevData.equals(r4Data) => None
          case _ => Some(r4Data)
        }
      case None => Some(r4Data)
    }
  }

  /**
    * Executes the 5.1-st round of the DKG protocol.
    *
    * Checks complaints from non-disqualified members, contained in r4DataIn.
    * In case of at least one valid complaint, the violator's opened share (decrypted secret share, received from round 1) is posted. The corresponding member is also listed as a protocol violator and will be ignored during the further protocol execution.
    * Opened shares of the 3-rd round absentees are also posted.
    *
    * Shares to be posted are placed into the R5_1Data structure, which should be passed to all other members of the DKG protocol.
    * When a data from the previous execution of this round (prevR5_1Data) is supplied, the check for identity of generated R5_1Data and prevR5_1Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR5_1Data and newly generated R5_1Data are inconsistent and None is returned, the generated R5_1Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R5_1Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r4DataIn a sequence of R4Data packets of all protocol members (including the own one).
    * @param prevR5_1Data optional, R5_1Data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R5_1Data) if success, None otherwise
    */
  def doRound5_1(r4DataIn: Seq[R4Data], prevR5_1Data: Option[R5_1Data] = None): Option[R5_1Data] = {

    def checkComplaint(violatorsCommitment: Commitment, complaint: ComplaintR4): Boolean = {
      val violatorsCRSCommitment = CRS_commitments.find(_.issuerID == complaint.violatorID).get
      val CRS_Ok = checkOnCRS(ctx, complaint.share_a, complaint.share_b, violatorsCRSCommitment.crs_commitment.map(_.bytes))

      val share = Share(complaint.violatorID, complaint.share_a, complaint.share_b)
      val Commitment_Ok = checkCommitmentR3(ctx, share, violatorsCommitment.commitment.map(_.bytes))

      CRS_Ok && !Commitment_Ok
    }

    roundsPassed match {
      case 5 => return roundsDataCache.r5_1Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 4) => return None // Round should be executed strictly after the previous round
      case 4 =>
    }

    val violatorsShares = ArrayBuffer[(Int, OpenedShare)]()

    val r4Data = r4DataIn.filter(x => {
      !violatorsIDs.contains(x.issuerID) &&
      !absenteesIDs.contains(x.issuerID)})

    for(i <- r4Data.indices) {
      for(j <- r4Data(i).complaints.indices) {
        val violatorID = r4Data(i).complaints(j).violatorID

        if(violatorID != ownID &&
          !violatorsShares.exists(_._1 == violatorID)) {

          val violatorShare = shares.find(_.issuerID == violatorID)
          val violatorCommitment = commitments.find(_.issuerID == violatorID)

          if(violatorCommitment.isDefined) {
            if(checkComplaint(violatorCommitment.get, r4Data(i).complaints(j))) {
              if(violatorShare.isDefined)
                violatorsShares += Tuple2(violatorID, violatorShare.get.share_a)

              // Deleting commitment A of the violator
              commitments -= violatorCommitment.get

              if(!violatorsIDs.contains(violatorID))
                violatorsIDs += violatorID
            }
          }
          else if(violatorShare.isDefined) {
            // Commitment of the violator is absent, because it wasn't accepted on the round 4. So just post the share of the violator.
            violatorsShares += Tuple2(violatorID, violatorShare.get.share_a)
          }
        }
      }
    }

    // Post shares for 3-rd round absentees, as their keys also should be reconstructed
    absenteesIDs.foreach(absenteeID => {
      val absenteeShare = shares.find(_.issuerID == absenteeID)
      if(absenteeShare.isDefined)
        violatorsShares += Tuple2(absenteeID, absenteeShare.get.share_a)
    })

    val r5_1Data = R5_1Data(ownID, violatorsShares.sortBy(_._1))

    roundsPassed += 1
    roundsDataCache.r5_1Data = Seq(r5_1Data) // round output is always cached

    prevR5_1Data match {
      case Some(data) =>
        val prevR5_1DataSorted = R5_1Data(data.issuerID, data.violatorsShares.sortBy(_._1))
        prevR5_1DataSorted match {
          case prevData if !prevData.equals(r5_1Data) => None
          case _ => Some(r5_1Data)
        }
      case None => Some(r5_1Data)
    }
  }

  /**
    * Executes the 5.2-nd round of the DKG protocol.
    *
    * Gathers shares of disqualified members, which has been posted by all protocol members in R5_1Data.
    * Using gathered shares reconstructs secrets of disqualified members and obtains their individual public keys.
    * Using the round 3 commitments of present members and reconstructed public keys of disqualified members obtains a common shared public key.
    *
    * Reconstructed secret keys and shared public key are placed into the R5_2Data structure.
    * When a data from the previous execution of this round (prevR5_2Data) is supplied, the check for identity of generated R5_2Data and prevR5_2Data will be performed. This check is needed for state consistency control.
    * Output of the current round execution is always cached.
    * In case if prevR5_2Data and newly generated R5_2Data are inconsistent and None is returned, the generated R5_2Data can be retrieved from the roundsDataCache.
    * If this method is called more than once during the same protocol execution, the cached R5_2Data from the firstest method execution will be returned.
    * If this method is called out of the supposed by the protocol order, then None will be returned.
    *
    * @param r5_1DataIn a sequence of R5_1Data packets of all protocol members (including the own one).
    * @param prevR5_2Data optional, R5_2Data from previous execution of this round (should be passed during internal state restoring)
    * @return Some(R5_2Data) if success, None otherwise
    */
  def doRound5_2(r5_1DataIn: Seq[R5_1Data], prevR5_2Data: Option[R5_2Data] = None): Option[R5_2Data] = {

    roundsPassed match {
      case 6 => return roundsDataCache.r5_2Data.headOption // Round is already executed, return the cashed round output
      case r if (r != 5) => return None // Round should be executed strictly after the previous round
      case 5 =>
    }

    val violatorsShares = new ArrayBuffer[ViolatorShare]

    val r5_1Data = r5_1DataIn.filter(x => {
      !violatorsIDs.contains(x.issuerID) &&
      !absenteesIDs.contains(x.issuerID)})

    // Retrieving shares of each violator
    for(i <- r5_1Data.indices) {
      for(j <- r5_1Data(i).violatorsShares.indices) {
        val violatorID = r5_1Data(i).violatorsShares(j)._1

        if(violatorID != ownID) {
          val violatorShare = r5_1Data(i).violatorsShares(j)._2

          if(violatorsShares.exists(_.violatorID == violatorID))
            violatorsShares.find(_.violatorID == violatorID).get.violatorShares += violatorShare
          else
            violatorsShares += ViolatorShare(violatorID, new ArrayBuffer[OpenedShare]() += violatorShare)
        }
      }
    }

    // All keys should be recovered
    val sufficientNumOfShares =
      violatorsShares.forall{
        vs =>
          vs.violatorShares.length >= t
      }

    val r5_2Data = {

      if(sufficientNumOfShares){

        val violatorsSecretKeys = for(i <- violatorsShares.indices) yield {
          SecretKey(violatorsShares(i).violatorID, LagrangeInterpolation.restoreSecret(ctx, violatorsShares(i).violatorShares, t).toByteArray)
        }

        val violatorsPublicKeys = for(i <- violatorsSecretKeys.indices) yield {
          g.pow(BigInt(violatorsSecretKeys(i).secretKey)).get
        }

        var honestPublicKeysSum = A(0) // own public key
        for(i <- commitments.indices) {
          honestPublicKeysSum = honestPublicKeysSum.multiply(commitments(i).commitment(0)).get
        }

        var violatorsPublicKeysSum: GroupElement = group.groupIdentity
        for(i <- violatorsPublicKeys.indices) {
          violatorsPublicKeysSum = violatorsPublicKeysSum.multiply(violatorsPublicKeys(i)).get
        }

        val sharedPublicKey = honestPublicKeysSum.multiply(violatorsPublicKeysSum).get

        R5_2Data(ownID, sharedPublicKey.bytes, violatorsSecretKeys.sortBy(_.ownerID).toArray)

      } else {
        R5_2Data(ownID, group.groupIdentity.bytes, Array[SecretKey]())
      }
    }

    roundsPassed += 1
    roundsDataCache.r5_2Data = Seq(r5_2Data) // round output is always cached

    prevR5_2Data match {
      case Some(data) =>
        val prevR5_2DataSorted = R5_2Data(data.issuerID, data.sharedPublicKey, data.violatorsSecretKeys.sortBy(_.ownerID))
        prevR5_2DataSorted match {
          case prevData if !prevData.equals(r5_2Data) => None
          case _ => Some(r5_2Data)
        }
      case None => Some(r5_2Data)
    }
  }

  /**
    * Restores internal state up to a certain round of the DKG protocol.
    *
    * Sequentially executes the DKG round functions, depending on available data from previously executed rounds.
    * Round function can be executed, if data from previous round and own data for current round is available in roundsData.
    * Availability of an own data in a certain round means, that round has been already locally executed, thus the local DKG state should be accordingly modified.
    *
    * NOTE (for usage in the DLT systems):
    * When collecting roundsData, in the incomplete round the own data should be searched in a mempool as well as in a history.
    *
    * @param roundsData data of all protocol members for all rounds, which has been already executed
    * @return Success(Unit) if current state has been restored successfully;
    *         Failure(e)    if an error during state restoring has occurred (mainly because of inconsistency of newly generated and previously obtained own round data).
    */
  def initialize(roundsData: RoundsData): Try[Unit] = Try {

    val ownRound1Data = roundsData.r1Data.find(_.issuerID == ownID)
    val ownRound2Data = roundsData.r2Data.find(_.issuerID == ownID)
    val ownRound3Data = roundsData.r3Data.find(_.issuerID == ownID)
    val ownRound4Data = roundsData.r4Data.find(_.issuerID == ownID)
    val ownRound5_1Data = roundsData.r5_1Data.find(_.issuerID == ownID)
    val ownRound5_2Data = roundsData.r5_2Data.find(_.issuerID == ownID)

    if (ownRound1Data.isDefined)
    {
      val r1Data = doRound1(ownRound1Data)
      require(r1Data.isDefined, "r1Data != ownRound1Data")

      if (ownRound2Data.isDefined && roundsData.r1Data.nonEmpty)
      {
        val r2Data = doRound2(roundsData.r1Data, ownRound2Data)
        require(r2Data.isDefined, "r2Data != ownRound2Data")

        if (ownRound3Data.isDefined && roundsData.r2Data.nonEmpty)
        {
          val r3Data = doRound3(roundsData.r2Data, ownRound3Data)
          require(r3Data.isDefined, "r3Data != ownRound3Data")

          if (ownRound4Data.isDefined && roundsData.r3Data.nonEmpty)
          {
            val r4Data = doRound4(roundsData.r3Data, ownRound4Data)
            require(r4Data.isDefined, "r3Data != ownRound4Data")

            if (ownRound5_1Data.isDefined && roundsData.r4Data.nonEmpty)
            {
              val r5_1Data = doRound5_1(roundsData.r4Data, ownRound5_1Data)
              require(r5_1Data.isDefined, "r5_1Data != ownRound5_1Data")

              if (ownRound5_2Data.isDefined && roundsData.r5_1Data.nonEmpty)
              {
                val r5_2Data = doRound5_2(roundsData.r5_1Data, ownRound5_2Data)
                require(r5_2Data.isDefined, "r5_2Data != ownRound5_2Data")
              }
            }
          }
        }
      }
    }
  }
}

object DistrKeyGen {

  private def checkOnCRS(ctx: CryptoContext,
                         share_a: OpenedShare,
                         share_b: OpenedShare,
                         E: Array[Array[Byte]]): Boolean = {
    import ctx.group
    val crs = ctx.commonReferenceString.get

    var E_sum: GroupElement = group.groupIdentity

    for(i <- E.indices) {
      E_sum = E_sum.multiply(group.reconstructGroupElement(E(i)).get.pow(BigInt(share_a.receiverID.toLong + 1).pow(i))).get
    }
    val CRS_Shares = group.groupGenerator.pow(BigInt(share_a.S.decryptedMessage)).flatMap {
      _.multiply(crs.pow(BigInt(share_b.S.decryptedMessage)))
    }.get

    CRS_Shares.equals(E_sum)
  }

  private def checkComplaintR2(ctx:                CryptoContext,
                               complaint:         ComplaintR2,
                               secretShare:       ShareEncrypted,
                               memberIdentifier:  Identifier[Int],
                               E:                 Array[Array[Byte]]): Boolean = {
    import ctx.{blockCipher, group, hash}
    val crs = ctx.commonReferenceString.get

    def checkProof(pubKey: PubKey, proof: ShareProof): Boolean = {
      ElgamalDecrNIZK.verifyNIZK(
        pubKey,
        proof.encryptedShare.encryptedSymmetricKey,
        proof.decryptedShare.decryptedKey,
        proof.NIZKProof)
    }

    def checkEncryption(proof: ShareProof): Boolean = {
      val ciphertext = HybridEncryption.encrypt(
        group.groupIdentity,                     // for this verification no matter what public key is used
        proof.decryptedShare.decryptedMessage,
        proof.decryptedShare.decryptedKey).get

      val shareDecryptedCorrectly = ciphertext.encryptedMessage.equals(proof.encryptedShare.encryptedMessage)

      val receiverID = memberIdentifier.getId(complaint.issuerPublicKey)

      val complaintIsCorrect = {
        if (receiverID.isDefined){

          val share_a = OpenedShare(receiverID.get, complaint.shareProof_a.decryptedShare)
          val share_b = OpenedShare(receiverID.get, complaint.shareProof_b.decryptedShare)

          // Check, that decrypted shares corresponds to the previously submitted secret shares
          // Check, that shares doesn't correspond to the submitted CRS commitments
          sharesAreEqual(ctx, share_a, secretShare.share_a) &&
          sharesAreEqual(ctx, share_b, secretShare.share_b) &&
          !checkOnCRS(ctx, share_a, share_b, E)

        } else {
          false
        }
      }
      shareDecryptedCorrectly && complaintIsCorrect
    }

    val publicKey = complaint.issuerPublicKey
    val proof_a = complaint.shareProof_a
    val proof_b = complaint.shareProof_b

    (checkProof(publicKey, proof_a) && checkEncryption(proof_a)) &&
      (checkProof(publicKey, proof_b) && checkEncryption(proof_b))
  }

  private def checkCommitmentR3(ctx: CryptoContext,
                                share: Share,
                                commitment: Array[Array[Byte]]): Boolean = {
    import ctx.group

    val A = commitment.map(group.reconstructGroupElement(_).get)
    val X = BigInt(share.share_a.receiverID.toLong + 1)

    var A_sum: GroupElement = group.groupIdentity

    for(i <- A.indices) {
      A_sum = A_sum.multiply(A(i).pow(X.pow(i)).get).get
    }

    val share_a = BigInt(share.share_a.S.decryptedMessage)
    val g_sa = group.groupGenerator.pow(share_a).get

    g_sa.equals(A_sum)
  }

  /**
    * Verifies, if a decrypted share corresponds to a specififc encrypted share.
    * Verification consists in an encryption of the decrypted share (using its opened symmetric key) and checking the obtained ciphertext for equality with the encrypted share.
    *
    * @param ctx cryptosystem, used for the protocol running;
    * @param openedShare decypted share;
    * @param secretShare encrypted share;
    * @return true, if shares are equal.
    */
  def sharesAreEqual(ctx:         CryptoContext,
                     openedShare: OpenedShare,
                     secretShare: SecretShare): Boolean = {

    import ctx.{blockCipher, group}

    val shareCiphertext = HybridEncryption.encrypt(
      group.groupIdentity,                     // for this verification no matter what public key is used
      openedShare.S.decryptedMessage,
      openedShare.S.decryptedKey
    ).get

    // Check if an encrypted opened share is the same as secret share
    secretShare.S.encryptedMessage.bytes.sameElements(
      shareCiphertext.encryptedMessage.bytes
    )
  }

  /**
    * Retrieves the IDs of disqualified after round 1 members of the DKG protocol.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param membersPubKeys public keys of all registered protocol members;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param r1Data a sequence of posted during the 1-st round R1Data packets of all protocol members;
    * @param r2Data a sequence of posted during the 2-nd round R2Data packets of all protocol members;
    * @return a sequence of IDs of disqualified after round 1 protocol members.
    */
  def getDisqualifiedOnR1CommitteeMembersIDs(ctx: CryptoContext,
                                             membersPubKeys: Seq[PubKey],
                                             memberIdentifier: Identifier[Int],
                                             r1Data: Seq[R1Data],
                                             r2Data: Seq[R2Data] = Seq()): Seq[Int] = {
    val allMembersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)

    val absenteesR1 = allMembersIDs.diff(r1Data.map(_.issuerID))
    val r2DataFiltered = r2Data.filter(r2 => !absenteesR1.contains(r2.issuerID)) // cut off possible data from R1 absentees
    val violatorsR1 =
      r2DataFiltered.foldLeft(Set[Int]()){
        (acc, r2) => acc ++ r2.complaints.foldLeft(Set[Int]()){
          (acc, c) => acc + c.violatorID
        }
      }.toSeq
    val disqualifiedMembersOnR1 = absenteesR1 ++ violatorsR1
    disqualifiedMembersOnR1
  }

  /**
    * Retrieves the IDs of disqualified after round 3 members of the DKG protocol.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param membersPubKeys public keys of all registered protocol members;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param disqualifiedMembersOnR1 a sequence of IDs of disqualified after round 1 protocol members;
    * @param r3Data a sequence of posted during the 3-rd round R3Data packets of all protocol members;
    * @param r4Data a sequence of posted during the 4-th round R4Data packets of all protocol members;
    * @return a sequence of IDs of disqualified after round 3 protocol members.
    */
  def getDisqualifiedOnR3CommitteeMembersIDs(ctx: CryptoContext,
                                             membersPubKeys: Seq[PubKey],
                                             memberIdentifier: Identifier[Int],
                                             disqualifiedMembersOnR1: Seq[Int],
                                             r3Data: Seq[R3Data],
                                             r4Data: Seq[R4Data] = Seq()): Seq[Int] = {
    val allMembersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)

    val r3DataFiltered = r3Data.filter(r3 =>
      !disqualifiedMembersOnR1.contains(r3.issuerID))
    val absenteesR3 =
      allMembersIDs.diff(disqualifiedMembersOnR1).diff(r3DataFiltered.map(_.issuerID))

    val r4DataFiltered = r4Data.filter(r4 =>
      !disqualifiedMembersOnR1.contains(r4.issuerID) &&
        !absenteesR3.contains(r4.issuerID)) // cut off possible data from R1 disqualified members and R3 absentees
    val violatorsR3 =
      r4DataFiltered.foldLeft(Set[Int]()){
        (acc, r4) => acc ++ r4.complaints.foldLeft(Set[Int]()){
          (acc, c) => acc + c.violatorID
        }
      }.toSeq
    val disqualifiedMembersOnR3 = absenteesR3 ++ violatorsR3
    disqualifiedMembersOnR3
  }

  /**
    * Retrieve all committee members disqualified during the distributed key generation
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param membersPubKeys pub keys of all registered committee members
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param r1Data a sequence of posted during the 1-st round R1Data packets of all protocol members;
    * @param r2Data a sequence of posted during the 2-nd round R2Data packets of all protocol members;
    * @param r3Data a sequence of posted during the 3-rd round R3Data packets of all protocol members;
    * @param r4Data a sequence of posted during the 4-th round R4Data packets of all protocol members;
    * @return pub keys of the disqualified CMs
    */
  def getAllDisqualifiedCommitteeMembersPubKeys(ctx: CryptoContext,
                                                membersPubKeys: Seq[PubKey],
                                                memberIdentifier: Identifier[Int],
                                                r1Data: Seq[R1Data],
                                                r2Data: Seq[R2Data],
                                                r3Data: Seq[R3Data],
                                                r4Data: Seq[R4Data]): Seq[PubKey] = {
    val disqualifiedMembersOnR1 =
      getDisqualifiedOnR1CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, r1Data, r2Data)

    val disqualifiedMembersOnR3 =
      getDisqualifiedOnR3CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, disqualifiedMembersOnR1, r3Data, r4Data)

    (disqualifiedMembersOnR1 ++ disqualifiedMembersOnR3).map(memberIdentifier.getPubKey(_).get)
  }

  def recoverKeysOfDisqualifiedOnR3Members(ctx: CryptoContext,
                                           numberOfMembers: Int,
                                           r5_1Data: Seq[R5_1Data],
                                           disqualifiedMembersOnR1: Seq[Int],
                                           disqualifiedMembersOnR3: Seq[Int]): Seq[(PubKey, PrivKey)] = {
    import ctx.group

    val r5_1DataFiltered = r5_1Data.filter(
      r5 =>
        !disqualifiedMembersOnR1.contains(r5.issuerID) &&
          !disqualifiedMembersOnR3.contains(r5.issuerID)
    )

    val disqualifiedR3MembersShares = new ArrayBuffer[ViolatorShare]

    // Retrieving shares of each disqualified at round 3 member
    r5_1DataFiltered.foreach {
      _.violatorsShares.foreach{
        share =>
          val (violatorID, violatorShare) = share

          disqualifiedR3MembersShares.find(_.violatorID == violatorID) match {
            case Some(vs) => vs.violatorShares += violatorShare
            case _ => disqualifiedR3MembersShares += ViolatorShare(violatorID, new ArrayBuffer[OpenedShare] += violatorShare)
          }
      }
    }

    val t = (numberOfMembers.toFloat / 2).ceil.toInt

    // All keys should be recovered
    val sufficientNumOfShares =
      disqualifiedR3MembersShares.forall{
      vs =>
        vs.violatorShares.length >= t
    }

    if (sufficientNumOfShares){
      val violatorsSecretKeys = disqualifiedR3MembersShares.map(
        share => LagrangeInterpolation.restoreSecret(ctx, share.violatorShares, t)
      )
      val violatorsPublicKeys = violatorsSecretKeys.map(group.groupGenerator.pow(_).get)

      violatorsPublicKeys zip violatorsSecretKeys
    } else {
      Seq[(PubKey, PrivKey)]()
    }
  }

  /**
    * Calculates a shared public key, using a data, generated during execution of the rounds 1 - 5.1 of the DKG protocol.
    *
    * @param ctx cryptosystem, which should be used for a shared public key calculation
    * @param membersPubKeys public keys of all members, who participated in DKG protocol
    * @param memberIdentifier generator of members identifiers, based on the list of members public keys (membersPubKeys)
    * @param roundsData data of all protocol members for the rounds 1 - 5.1
    * @return Success(SharedPublicKey), where the SharedPublicKey is an encoded to a byte representation shared public key - in case of success;
    *         Failure(e) - if an error during computations has occurred.
    */
  def getSharedPublicKey (ctx:                      CryptoContext,
                          membersPubKeys:           Seq[PubKey],
                          memberIdentifier:         Identifier[Int],
                          roundsData:               RoundsData): Try[SharedPublicKey] = Try {
    import ctx.group

    val disqualifiedMembersOnR1 =
      getDisqualifiedOnR1CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, roundsData.r1Data, roundsData.r2Data)

    val disqualifiedMembersOnR3 =
      getDisqualifiedOnR3CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, disqualifiedMembersOnR1, roundsData.r3Data, roundsData.r4Data)

    val n = membersPubKeys.length // total number of members
    val t = (n.toFloat / 2).ceil.toInt // threshold (minimal) number of members

    val totalNumberOfDisqualifiedMembers = disqualifiedMembersOnR1.length + disqualifiedMembersOnR3.length
    require(
      totalNumberOfDisqualifiedMembers <= (n - t),
      s"Number of disqualified members ($totalNumberOfDisqualifiedMembers) exceeds the reconstruction threshold ($t)")

    val recoveredViolatorsKeys =
      recoverKeysOfDisqualifiedOnR3Members(ctx, membersPubKeys.size, roundsData.r5_1Data, disqualifiedMembersOnR1, disqualifiedMembersOnR3)
    require(
      recoveredViolatorsKeys.map(keyPair => memberIdentifier.getId(keyPair._1).get).sorted.equals(disqualifiedMembersOnR3.sorted), // the identifiers of members, which keys are restored, are the same as identifiers of disqualified on R3 members
      "Not all keys have been reconstructed")

    val r3Data = roundsData.r3Data.filter(r3 => !disqualifiedMembersOnR1.contains(r3.issuerID))
    val validCommitments =
      r3Data.filter(r3 => !disqualifiedMembersOnR3.contains(r3.issuerID)).
        map(r3 => Commitment(r3.issuerID, r3.commitments.map(group.reconstructGroupElement(_).get)))

    val honestPublicKeysSum = validCommitments.foldLeft(group.groupIdentity){
      (acc, c) => acc.multiply(c.commitment.head).get
    }

    val violatorsPublicKeysSum = recoveredViolatorsKeys.foldLeft(group.groupIdentity){
      (acc, keys) => acc.multiply(keys._1).get
    }

    val sharedPublicKey = honestPublicKeysSum.multiply(violatorsPublicKeysSum).get
    require(
      !sharedPublicKey.equals(group.groupIdentity),
      "Shared public key is undefined")

    sharedPublicKey.bytes
  }

  /**
    * Generates a recovery share for the faulty committee member. Basically recovery share is a decrypted share that
    * was previously (in Round 1) submitted by the faulty CM.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param keys private and public key of a CM who generates recovery share
    * @param violatorPubKey public key of a CM for whom the recovery share is generated
    * @param r1Data submitted encrypted shares for all CMs
    * @return OpenedShare
    */
  def generateRecoveryKeyShare(ctx: CryptoContext,
                               memberIdentifier: Identifier[Int],
                               keys: (PrivKey, PubKey),
                               violatorPubKey: PubKey,
                               r1Data: Seq[R1Data]): Try[OpenedShare] = Try {
    import ctx.{blockCipher, group}

    val (myPrivKey, myPubKey) = keys
    val myId = memberIdentifier.getId(myPubKey).get
    val violatorId = memberIdentifier.getId(violatorPubKey).get

    val shareForMeFromViolator = r1Data.find(_.issuerID == violatorId).get.S_a.find(_.receiverID == myId).get
    OpenedShare(shareForMeFromViolator.receiverID, HybridEncryption.decrypt(myPrivKey, shareForMeFromViolator.S).get)
  }

  /**
    * Validates an OpenedShare submitted by a committee member. Basically OpenedShare is a decrypted share which was
    * submitted on Round 1. So the verification process encrypts the provided OpenedShare and verifies that it is the
    * same as was submitted at Round 1.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param issuerPubKey public key of a CM who generates recovery share
    * @param violatorPubKey public key of a CM for whom the recovery share is generated
    * @param r1Data submitted encrypted shares for all CMs
    * @param openedShare openedShare for verification
    * @return Try(Success(Unit)) if succeeds
    */
  def validateRecoveryKeyShare(ctx: CryptoContext,
                               memberIdentifier: Identifier[Int],
                               issuerPubKey: PubKey,
                               violatorPubKey: PubKey,
                               r1Data: Seq[R1Data],
                               openedShare: OpenedShare): Try[Unit] = Try {
    val issuerId = memberIdentifier.getId(issuerPubKey).get
    val violatorId = memberIdentifier.getId(violatorPubKey).get
    val submittedShare = r1Data.find(_.issuerID == violatorId).get.S_a.find(_.receiverID == issuerId).get

    require(sharesAreEqual(ctx, openedShare, submittedShare), "OpenedShare doesn't conform to the submitted share")
  }

  /**
    * Recovers committee member public key by openedShares from other CMs. Note that the recovered privKey (and corresponding pubKey)
    * is not related to the proxy key that was registered by the committee member. Those proxy keys are used only to encrypt
    * personal shares during the round 1. The public key for the distributed key generation is never registrated directly and is
    * revealed only at Round 3 as first component of the commitment array A.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param numberOfMembers number of the all registered protocol members;
    * @param openedShares opened shares from other CMs. There should be shares from at least half of the CMs
    * @param pubKeyOfRecoveredPrivKey is used only for additional verification. If provided the recovered priv/pub keys will
    *                                 be verified by this key (pub keys should be the same)
    * @return
    */
  def recoverPrivateKeyByOpenedShares(ctx: CryptoContext,
                                      numberOfMembers: Int,
                                      openedShares: Seq[OpenedShare],
                                      pubKeyOfRecoveredPrivKey: Option[PubKey] = None): Try[PrivKey] = Try {
    import ctx.group

    val recoveryThreshold = (numberOfMembers.toFloat / 2).ceil.toInt
    require(openedShares.size >= recoveryThreshold, "Not enough opened shares to recover a key")

    val recoveredPrivKey = LagrangeInterpolation.restoreSecret(ctx, openedShares, recoveryThreshold)

    if (pubKeyOfRecoveredPrivKey.isDefined) {
      val recoveredPubKey = group.groupGenerator.pow(recoveredPrivKey).get
      require(recoveredPubKey == pubKeyOfRecoveredPrivKey.get, "Recovered key doesn't conform to the given pub key")
    }

    recoveredPrivKey
  }

  /**
    * Verifies for validity the 1-st round's data, submitted by a certain member of the DKG protocol.
    * Verification can be performed externally, without being a member of the protocol.
    *
    * @param r1Data round 1 data, submitted by a certain protocol member;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param membersPubKeys public keys of the all members of the protocol;
    * @return Success(Unit) if submitted r1Data is valid;
    *         Failure(e)    otherwise.
    */
  def checkR1Data(r1Data:           R1Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey]): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r1Data.issuerID), "Illegal issuer's ID")

    val membersNum = membersPubKeys.length
    val t = (membersNum.toFloat / 2).ceil.toInt

    require(r1Data.E.length   == t, "Incorrect number of CRS commitments")
    require(r1Data.S_a.length == membersNum - 1, "Incorrect number of S_a secret shares")
    require(r1Data.S_b.length == membersNum - 1, "Incorrect number of S_b secret shares")

    require(r1Data.S_a.map(_.receiverID).distinct.length == r1Data.S_a.map(_.receiverID).length, "Duplicates of S_a secret shares receivers are present")
    require(r1Data.S_b.map(_.receiverID).distinct.length == r1Data.S_b.map(_.receiverID).length, "Duplicates of S_b secret shares receivers are present")

    // CRS commitment validity can verify only a member of DKG protocol, as a private key for secret shares decryption is needed
  }

  /**
    * Verifies for validity the 2-nd round's data, submitted by a certain member of the DKG protocol.
    * Verification can be performed externally, without being a member of the protocol.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param r2Data round 2 data, submitted by a certain protocol member;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param membersPubKeys public keys of the all members of the protocol;
    * @param r1DataSeq a sequence of posted during the 1-st round R1Data packets of all protocol members;
    * @return Success(Unit) if submitted r2Data is valid;
    *         Failure(e)    otherwise.
    */
  def checkR2Data(ctx:              CryptoContext,
                  r2Data:           R2Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey],
                  r1DataSeq:        Seq[R1Data]): Try[Unit] = Try {
    val crs = ctx.commonReferenceString.get

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r2Data.issuerID), "Illegal issuer's ID")

    val disqualifiedMembersIds = getDisqualifiedOnR1CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, r1DataSeq) // here CM can be verified only for absence on R1 (R2 is running, full set of R2 complaints isn't posted yet)
    require(!disqualifiedMembersIds.contains(r2Data.issuerID), "Issuer has been disqualified on R1")

    val membersNum = membersPubKeys.length
    require(r2Data.complaints.length <= membersNum, "Exceeding number of R2 complaints")

    val complaintsIDs = r2Data.complaints.map(_.violatorID)
    require(complaintsIDs.distinct.length == complaintsIDs.length, "Duplicates of R2 complaints are present")

    def checkComplaint(complaint: ComplaintR2): Boolean = {

      val r1DataOpt = r1DataSeq.find(_.issuerID == complaint.violatorID)
      require(r1DataOpt.isDefined, s"Missing R1 data of ${complaint.violatorID}")

      val secretShare_a = r1DataOpt.get.S_a.find(_.receiverID == r2Data.issuerID)
      val secretShare_b = r1DataOpt.get.S_b.find(_.receiverID == r2Data.issuerID)

      require(secretShare_a.isDefined, s"Missing secret share from ${complaint.violatorID} for ${r2Data.issuerID}")
      require(secretShare_b.isDefined, s"Missing secret share from ${complaint.violatorID} for ${r2Data.issuerID}")

      val secretShare = ShareEncrypted(complaint.violatorID, secretShare_a.get, secretShare_b.get)

      checkComplaintR2(ctx, complaint, secretShare, memberIdentifier, r1DataOpt.get.E)
    }

    r2Data.complaints.foreach {
      c =>
        require(membersIDs.contains(c.violatorID), "Illegal violator's ID")
        require(membersPubKeys.contains(c.issuerPublicKey), "Illegal issuer's public key")
        require(checkComplaint(c), "Illegal complaint R2")
    }
  }

  /**
    * Verifies for validity the 3-rd round's data, submitted by a certain member of the DKG protocol.
    * Verification can be performed externally, without being a member of the protocol.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param r3Data round 3 data, submitted by a certain protocol member;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param membersPubKeys public keys of the all members of the protocol;
    * @param r1DataSeq a sequence of posted during the 1-st round R1Data packets of all protocol members;
    * @param r2DataSeq a sequence of posted during the 2-nd round R2Data packets of all protocol members;
    * @return Success(Unit) if submitted r3Data is valid;
    *         Failure(e)    otherwise.
    */
  def checkR3Data(ctx:               CryptoContext,
                  r3Data:           R3Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey],
                  r1DataSeq:        Seq[R1Data],
                  r2DataSeq:        Seq[R2Data]): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r3Data.issuerID), "Illegal issuer's ID")

    val disqualifiedMembersIds = getDisqualifiedOnR1CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, r1DataSeq, r2DataSeq)
    require(!disqualifiedMembersIds.contains(r3Data.issuerID), "Issuer has been disqualified on R1")

    val membersNum = membersPubKeys.length
    val t = (membersNum.toFloat / 2).ceil.toInt

    require(r3Data.commitments.length == t, "Incorrect number of commitments")

    // Commitment validity can verify only a member of DKG protocol, as a set of decrypted on his private key shares is needed
  }

  /**
    * Verifies for validity the 4-th round's data, submitted by a certain member of the DKG protocol.
    * Verification can be performed externally, without being a member of the protocol.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param r4Data round 4 data, submitted by a certain protocol member;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param membersPubKeys public keys of the all members of the protocol;
    * @param r1DataSeq a sequence of posted during the 1-st round R1Data packets of all protocol members;
    * @param r2DataSeq a sequence of posted during the 2-nd round R2Data packets of all protocol members;
    * @param r3DataSeq a sequence of posted during the 3-rd round R3Data packets of all protocol members;
    * @return Success(Unit) if submitted r4Data is valid;
    *         Failure(e)    otherwise.
    */
  def checkR4Data(ctx:              CryptoContext,
                  r4Data:           R4Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey],
                  r1DataSeq:        Seq[R1Data],
                  r2DataSeq:        Seq[R2Data],
                  r3DataSeq:        Seq[R3Data]): Try[Unit] = Try {
    val crs = ctx.commonReferenceString.get

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r4Data.issuerID), "Illegal issuer's ID")

    val disqualifiedMembersIdsOnR1 = getDisqualifiedOnR1CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, r1DataSeq, r2DataSeq) // here CM can be verified only for absence on R3 (R4 is running, full set of R4 complaints isn't posted yet)
    require(!disqualifiedMembersIdsOnR1.contains(r4Data.issuerID), "Issuer has been disqualified on R1")

    val disqualifiedMembersIdsOnR3 = getDisqualifiedOnR3CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, disqualifiedMembersIdsOnR1, r3DataSeq)
    require(!disqualifiedMembersIdsOnR3.contains(r4Data.issuerID), "Issuer has been disqualified on R3")

    val membersNum = membersPubKeys.length
    require(r4Data.complaints.length <= membersNum, "Exceeding number of R4 complaints")

    def checkComplaintR4(complaint: ComplaintR4): Boolean = {

      val r1DataOpt = r1DataSeq.find(_.issuerID == complaint.violatorID)
      require(r1DataOpt.isDefined, s"R1 commitments are absent for ${complaint.violatorID}")

      val r3DataOpt = r3DataSeq.find(_.issuerID == complaint.violatorID)
      require(r3DataOpt.isDefined, s"R3 commitments are absent for ${complaint.violatorID}")

      val CRS_Ok = checkOnCRS(ctx, complaint.share_a, complaint.share_b, r1DataOpt.get.E)

      val share = Share(r1DataOpt.get.issuerID, complaint.share_a, complaint.share_b)
      val Commitment_Ok = checkCommitmentR3(ctx, share, r3DataOpt.get.commitments)

      CRS_Ok && !Commitment_Ok
    }

    val complaintsIDs = r4Data.complaints.map(_.violatorID)
    require(complaintsIDs.distinct.length == complaintsIDs.length, "Duplicates of R4 complaints are present")

    r4Data.complaints.foreach {
      c =>
        require(membersIDs.contains(c.violatorID), "Illegal violator's ID")
        require(c.share_a.receiverID == r4Data.issuerID, s"Share_a doesn't belong to the issuer ${r4Data.issuerID} (share_a receiver ID is ${c.share_a.receiverID})")
        require(c.share_b.receiverID == r4Data.issuerID, s"Share_a doesn't belong to the issuer ${r4Data.issuerID} (share_b receiver ID is ${c.share_b.receiverID})")
        require(checkComplaintR4(c), s"Illegal complaint on ${c.violatorID} from ${r4Data.issuerID}")
    }
  }

  /**
    * Verifies for validity the 5-th round's data, submitted by a certain member of the DKG protocol.
    * Verification can be performed externally, without being a member of the protocol.
    *
    * @param ctx cryptosystem, which should be used for the protocol running;
    * @param r5_1Data round 5 data, submitted by a certain protocol member;
    * @param memberIdentifier generator of protocol members IDs, based on a full set of protocol members public keys;
    * @param membersPubKeys public keys of the all members of the protocol;
    * @param r1DataSeq a sequence of posted during the 1-st round R1Data packets of all protocol members;
    * @param r2DataSeq a sequence of posted during the 2-nd round R2Data packets of all protocol members;
    * @param r3DataSeq a sequence of posted during the 3-rd round R3Data packets of all protocol members;
    * @param r4DataSeq a sequence of posted during the 4-th round R4Data packets of all protocol members;
    * @return Success(Unit) if submitted r5_1Data is valid;
    *         Failure(e)    otherwise.
    */
  def checkR5Data(ctx:              CryptoContext,
                  r5_1Data:         R5_1Data,
                  memberIdentifier: Identifier[Int],
                  membersPubKeys:   Seq[PubKey],
                  r1DataSeq:        Seq[R1Data],
                  r2DataSeq:        Seq[R2Data],
                  r3DataSeq:        Seq[R3Data],
                  r4DataSeq:        Seq[R4Data]): Try[Unit] = Try {

    val membersIDs = membersPubKeys.map(pk => memberIdentifier.getId(pk).get)
    require(membersIDs.contains(r5_1Data.issuerID), "Illegal issuer's ID")

    val disqualifiedMembersIdsOnR1 = getDisqualifiedOnR1CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, r1DataSeq, r2DataSeq)
    require(!disqualifiedMembersIdsOnR1.contains(r5_1Data.issuerID), "Issuer has been disqualified on R1")

    val disqualifiedMembersIdsOnR3 = getDisqualifiedOnR3CommitteeMembersIDs(ctx, membersPubKeys, memberIdentifier, disqualifiedMembersIdsOnR1, r3DataSeq, r4DataSeq)
    require(!disqualifiedMembersIdsOnR3.contains(r5_1Data.issuerID), "Issuer has been disqualified on R3")

    val membersNum = membersPubKeys.length
    require(r5_1Data.violatorsShares.length <= membersNum, "Exceeding number of R5_1 opened shares")

    def checkOpenedShare(shareIssuerID: Int, share: OpenedShare): Boolean = {

      val r1DataOpt = r1DataSeq.find(_.issuerID == shareIssuerID)
      require(r1DataOpt.isDefined, s"Missing secret shares of $shareIssuerID")

      val secretShareOpt = r1DataOpt.get.S_a.find(_.receiverID == share.receiverID)
      require(secretShareOpt.isDefined, s"Secret share for ${share.receiverID} is missing among secret shares of $shareIssuerID")

      // Check if an encrypted opened share is the same as previously submitted secret share
      sharesAreEqual(ctx, share, secretShareOpt.get)
    }

    val violatorsSharesIDs = r5_1Data.violatorsShares.map(_._1)
    require(violatorsSharesIDs.distinct.length == violatorsSharesIDs.length, "Duplicates of violators shares are present")

    r5_1Data.violatorsShares.foreach {
      s =>
        require(membersIDs.contains(s._1), "Illegal violator's ID")
        require(s._2.receiverID == r5_1Data.issuerID, s"Share doesn't belong to the issuer ${r5_1Data.issuerID} (share receiver ID is ${s._2.receiverID})")
        require(checkOpenedShare(s._1, s._2))
    }
  }
}