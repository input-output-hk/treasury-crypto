package treasury.crypto.keygen

import java.math.BigInteger

import org.bouncycastle.math.ec.ECPoint
import treasury.crypto.core.{Cryptosystem, KeyPair, Point, PubKey}

import scala.collection.mutable.ArrayBuffer

// Distributed Key Generation, based on Elliptic Curves
//
class DistrKeyGen(cs:                     Cryptosystem,
                  h:                      Point,
                  ownID:                  Integer,
                  transportKeyPair:       KeyPair,
                  committeeMembersAttrs:  Seq[CommitteeMemberAttr])
{
  case class CRS_commitment (issuerID: Integer, crs_commitment: Array[ECPoint])
  case class Commitment     (issuerID: Integer, commitment: Array[ECPoint])
  case class Share          (issuerID: Integer, share_a: OpenedShare, share_b: OpenedShare)

  private val CRS_commitments = new ArrayBuffer[CRS_commitment]() // CRS commitments of other participants
  private val commitments     = new ArrayBuffer[Commitment]()     // Commitments of other participants
  private val shares          = new ArrayBuffer[Share]()          // Shares of other participants
  private val violatorsIDs    = new ArrayBuffer[Integer]()        // ID' s of committee members-violators

  private val n = committeeMembersAttrs.size  // Total number of protocol participants
  private val t = (n.toFloat / 2).ceil.toInt  // Threshold number of participants
  private val A = new Array[ECPoint](t)       // Own commitments

  private val g = cs.basePoint
  private val infinityPoint = cs.infinityPoint

  private val ownPrivateKey = transportKeyPair._1
  private val ownPublicKey  = transportKeyPair._2

  def doRound1(secretKey: Array[Byte]): R1Data =
  {
    val poly_a = new Polynomial(cs, new BigInteger(secretKey), t)
    val poly_b = new Polynomial(cs, new BigInteger(secretKey), t)

    val r1Data = R1Data(ownID, new Array[Array[Byte]](t), new Array[SecretShare](n-1), new Array[SecretShare](n-1))

    for(i <- A.indices)
      A(i) = g.multiply(poly_a(i))

    // CRS commitments for each coefficient of both polynomials
    //
    for(i <- r1Data.E.indices)
      r1Data.E(i) = A(i).add(h.multiply(poly_b(i))).getEncoded(true)

    val recipientsIDs = committeeMembersAttrs.map(_.id).filter(_ != ownID)

    // Secret shares for each committee member
    //
    for(i <- recipientsIDs.indices)
    {
      val x = i + 1 // avoid share for a_0 coefficient
      val X = BigInteger.valueOf(x)

      val receiverPublicKey = committeeMembersAttrs.find(_.id == recipientsIDs(i)).get.publicKey

      r1Data.S_a(i) = SecretShare(recipientsIDs(i), x, cs.hybridEncrypt(receiverPublicKey, poly_a(X).toByteArray))
      r1Data.S_b(i) = SecretShare(recipientsIDs(i), x, cs.hybridEncrypt(receiverPublicKey, poly_b(X).toByteArray))
    }
    r1Data
  }

  def checkOnCRS(share_a: OpenedShare, share_b: OpenedShare, E: Array[Array[Byte]]): Boolean =
  {
    var E_sum: ECPoint = infinityPoint

    for(i <- E.indices) {
        E_sum = E_sum.add(cs.decodePoint(E(i)).multiply(BigInteger.valueOf(share_a.x.toLong).pow(i)))
    }
    val CRS_Shares = g.multiply(new BigInteger(share_a.S.decryptedMessage)).add(h.multiply(new BigInteger(share_b.S.decryptedMessage)))

    CRS_Shares.equals(E_sum)
  }

  def doRound2(r1Data: Seq[R1Data]): R2Data =
  {
    var complains = new ArrayBuffer[ComplainR2]()

    // TODO: Check, that S_a.size == S_b.size
    for(i <- r1Data.indices)
    {
      for(j <- r1Data(i).S_a.indices)
      {
        if(r1Data(i).S_a(j).receiverID == ownID)
        {
          val secretShare_a = r1Data(i).S_a(j)
          val secretShare_b = r1Data(i).S_b(j)

          val share_a = OpenedShare(secretShare_a.receiverID, secretShare_a.x, cs.hybridDecrypt(ownPrivateKey, secretShare_a.S))
          val share_b = OpenedShare(secretShare_b.receiverID, secretShare_b.x, cs.hybridDecrypt(ownPrivateKey, secretShare_b.S))

          if(checkOnCRS(share_a, share_b, r1Data(i).E))
          {
            shares += Share(r1Data(i).issuerID, share_a, share_b)
            CRS_commitments += CRS_commitment(r1Data(i).issuerID, r1Data(i).E.map(x => cs.decodePoint(x)))
          }
          else
          {
            complains += ComplainR2(r1Data(i).issuerID)
            violatorsIDs += r1Data(i).issuerID
          }
        }
      }
    }
    R2Data(complains.toArray)
  }

  def doRound3(r2Data: Seq[R2Data]): R3Data =
  {
    // Remove received shares and commitments of disqualified committees (if they were verified successfully, but at least 1 complain on their issuer was received)
    //
    for(i <- r2Data.indices)
    {
      for(j <- r2Data(i).complains.indices)
      {
        // TODO: Check validity of the complain

        val violatorCRSCommitment = CRS_commitments.find(_.issuerID == r2Data(i).complains(j).violatorID)
        if(violatorCRSCommitment.isDefined)
          CRS_commitments -= violatorCRSCommitment.get

        val violatorShare = shares.find(_.issuerID == r2Data(i).complains(j).violatorID)
        if(violatorShare.isDefined){
          shares -= violatorShare.get
          violatorsIDs += r2Data(i).complains(j).violatorID
        }
      }
    }
    // Commitments of poly_a coefficients
    //
    R3Data(ownID, A.map(_.getEncoded(true)))
  }

  def checkCommitment(issuerID: Integer, commitment: Array[Array[Byte]]): Boolean =
  {
    val A = commitment.map(cs.decodePoint)
    var A_sum: ECPoint = infinityPoint
    val share = shares.find(_.issuerID == issuerID)
    if(share.isDefined)
    {
      val X = BigInteger.valueOf(share.get.share_a.x.toLong)

      for(i <- A.indices) {
          A_sum = A_sum.add(A(i).multiply(X.pow(i)))
      }

      val share_a = new BigInteger(share.get.share_a.S.decryptedMessage)
      val g_sa = g.multiply(share_a)

      g_sa.equals(A_sum)
    }
    else // commitment belongs to a disqualified committee
      false
  }

  def doRound4(r3Data: Seq[R3Data]): R4Data =
  {
    var complains = new ArrayBuffer[ComplainR4]()

    for(i <- r3Data.indices)
    {
      val issuerID = r3Data(i).issuerID
      val issuerCommitments = r3Data(i).commitments

      if(issuerID != ownID)
      {
        if(checkCommitment(issuerID, issuerCommitments)){
          commitments += Commitment(issuerID, issuerCommitments.map(cs.decodePoint))
        }
        else
        {
          val share = shares.find(_.issuerID == issuerID)
          if(share.isDefined) { // if committee is disqualified, its shares are already deleted from the local state of the current committee
            complains += ComplainR4(issuerID, share.get.share_a, share.get.share_b)
            violatorsIDs += issuerID
          }
        }
      }
    }

    R4Data(ownID, complains.toArray)
  }

  def doRound5_1(r4DataIn: Seq[R4Data]): R5_1Data =
  {
    def checkComplain(complain: ComplainR4): Boolean =
    {
      val violatorsCRSCommitment = CRS_commitments.find(_.issuerID == complain.violatorID).get
      val CRS_Ok = checkOnCRS(complain.share_a, complain.share_b, violatorsCRSCommitment.crs_commitment.map(_.getEncoded(true)))

      val violatorsCommitment = commitments.find(_.issuerID == complain.violatorID).get
      val Commitment_Ok = checkCommitment(complain.violatorID, violatorsCommitment.commitment.map(_.getEncoded(true)))

      CRS_Ok && !Commitment_Ok
    }

    val violatorsShares = ArrayBuffer[(Integer, OpenedShare)]()

    val r4Data = r4DataIn.filter(x => !violatorsIDs.contains(x.issuerID))

    for(i <- r4Data.indices)
    {
      for(j <- r4Data(i).complains.indices)
      {
        val violatorID = r4Data(i).complains(j).violatorID

        if(violatorID != ownID &&
          !violatorsShares.exists(_._1 == violatorID))
        {
          if(commitments.exists(_.issuerID == violatorID))
          {
            if(checkComplain(r4Data(i).complains(j)))
            {
              val violatorShare = (violatorID, shares.find(_.issuerID == violatorID).get.share_a)
              violatorsShares += violatorShare
              // Deleting commitment A of the violator
              commitments -= commitments.find(_.issuerID == violatorID).get
            }
          }
          else
          {
            val violatorShare = (violatorID, shares.find(_.issuerID == violatorID).get.share_a)
            violatorsShares += violatorShare
          }
        }
      }
    }

    R5_1Data(ownID, violatorsShares.toArray)
  }

  def doRound5_2(r5_1DataIn: Seq[R5_1Data]): R5_2Data =
  {
    case class ViolatorShare(violatorID: Integer, violatorShares: ArrayBuffer[OpenedShare])
    val violatorsShares = new ArrayBuffer[ViolatorShare]

    val r5_1Data = r5_1DataIn.filter(x => !violatorsIDs.contains(x.issuerID))

    // Retrieving shares of each violator
    for(i <- r5_1Data.indices)
    {
      for(j <- r5_1Data(i).violatorsShares.indices)
      {
        val violatorID = r5_1Data(i).violatorsShares(j)._1

        if(violatorID != ownID)
        {
          val violatorShare = r5_1Data(i).violatorsShares(j)._2

          if(violatorsShares.exists(_.violatorID == violatorID))
            violatorsShares.find(_.violatorID == violatorID).get.violatorShares += violatorShare
          else
            violatorsShares += ViolatorShare(violatorID, new ArrayBuffer[OpenedShare]()+= violatorShare)
        }
      }
    }

    val violatorsSecretKeys = for(i <- violatorsShares.indices) yield {
      SecretKey(violatorsShares(i).violatorID, LagrangeInterpolation.restoreSecret(cs, violatorsShares(i).violatorShares).toByteArray)
    }

    val violatorsPublicKeys = for(i <- violatorsSecretKeys.indices) yield {
      g.multiply(new BigInteger(violatorsSecretKeys(i).secretKey))
    }

    var honestPublicKeysSum = A(0) // own public key
    for(i <- commitments.indices){
      honestPublicKeysSum = honestPublicKeysSum.add(commitments(i).commitment(0))
    }

    var violatorsPublicKeysSum: ECPoint = cs.infinityPoint
    for(i <- violatorsPublicKeys.indices){
      violatorsPublicKeysSum = violatorsPublicKeysSum.add(violatorsPublicKeys(i))
    }

    val sharedPublicKey = honestPublicKeysSum.add(violatorsPublicKeysSum)

    R5_2Data(sharedPublicKey.getEncoded(true), violatorsSecretKeys.toArray)
  }
}
