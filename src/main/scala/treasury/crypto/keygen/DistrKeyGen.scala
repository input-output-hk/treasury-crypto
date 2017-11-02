package treasury.crypto.keygen

import java.math.{BigDecimal, BigInteger, MathContext}
import java.util.Random

import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.math.ec.ECPoint
import treasury.crypto.{Cryptosystem, Point}

import scala.collection.mutable.ArrayBuffer

// Distributed Key Generation, based on Elliptic Curves
//
class DistrKeyGen(cs: Cryptosystem,
                  ownID:                  Integer,
                  h:                      Point,
                  committeeMembersAttrs:  Seq[CommitteeMemberAttr])
{
  class Polynomial(a_0: BigInteger, p: BigInteger, degree: Integer)
  {
    private val polynomial = new Array[BigInteger](degree)

    // Generating random polynomial coefficients
    for(i <- polynomial.indices)
    {
      if(i == 0)
        polynomial(0) = a_0
      else
        polynomial(i) = randZp(p)
    }

    // Computing the polynomial value for specified x argument
    def apply(x: BigInteger): BigInteger = {
      var res = polynomial(0)
      for(i <- 1 until polynomial.length)
        res = polynomial(i).multiply(x.pow(i)).add(res).mod(p)
      res
    }

    // Retrieving the value of coefficient by index
    def apply(i: Integer): BigInteger = {
      polynomial(i)
    }
  }

  case class CRS_commitment(issuerID: Integer, csr_commitment: Array[ECPoint])
  case class Commitment(issuerID: Integer, commitment: Array[ECPoint])
  case class Share(issuerID: Integer, share_a: SecretShare, share_b: SecretShare)

  private val g = cs.basePoint

  val CRS_commitments = new ArrayBuffer[CRS_commitment]() // CRS commitments of other participants
  val commitments = new ArrayBuffer[Commitment]()         // Commitments of other participants
  val shares = new ArrayBuffer[Share]()                   // Shares of other participants

  val n = committeeMembersAttrs.size  // Total number of protocol participants
  val t = (n.toFloat / 2).ceil.toInt  // Threshold number of participants
  val A = new Array[ECPoint](t)       // Own commitments

  // Pseudorandom number generation in Zp field
  def randZp(p: BigInteger): BigInteger = {
    new BigInteger(p.bitLength(), new Random).mod(p)
  }

  def doRound1(secretKey: Array[Byte]): R1Data =
  {
    val poly_a = new Polynomial(new BigInteger(secretKey), cs.orderOfBasePoint, t)
    val poly_b = new Polynomial(new BigInteger(secretKey), cs.orderOfBasePoint, t)

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

      // TODO: Add encryption of shares
      r1Data.S_a(i) = SecretShare(recipientsIDs(i), x, poly_a(X).toByteArray)
      r1Data.S_b(i) = SecretShare(recipientsIDs(i), x, poly_b(X).toByteArray)
    }
    r1Data
  }

  def checkOnCSR(share_a: SecretShare, share_b: SecretShare, E: Array[Array[Byte]]): Boolean =
  {
    var E_sum: ECPoint = null

    for(i <- E.indices)
    {
      if(E_sum == null)
        E_sum = cs.decodePoint(E(i)).multiply(BigInteger.valueOf(share_a.x.toLong).pow(i))
      else
        E_sum = E_sum.add(cs.decodePoint(E(i)).multiply(BigInteger.valueOf(share_a.x.toLong).pow(i)))
    }

    val CSR_Shares = g.multiply(new BigInteger(share_a.S)).add(h.multiply(new BigInteger(share_b.S)))

    CSR_Shares.equals(E_sum)
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
          if(checkOnCSR(r1Data(i).S_a(j), r1Data(i).S_b(j), r1Data(i).E))
          {
            shares += Share(r1Data(i).issuerID, r1Data(i).S_a(j), r1Data(i).S_b(j))
            CRS_commitments += CRS_commitment(r1Data(i).issuerID, r1Data(i).E.map(x => cs.decodePoint(x)))
          }
          else
            complains += ComplainR2(r1Data(i).issuerID)
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

        val violatorCSRCommitment = CRS_commitments.find(_.issuerID == r2Data(i).complains(j).violatorID)
        if(violatorCSRCommitment.isDefined)
          CRS_commitments -= violatorCSRCommitment.get

        val violatorShare = shares.find(_.issuerID == r2Data(i).complains(j).violatorID)
        if(violatorShare.isDefined)
          shares -= violatorShare.get
      }
    }

    // Commitments of poly_a coefficients
    //
    R3Data(ownID, A.map(x => x.getEncoded(true)))
  }

  def checkCommitment(issuerID: Integer, commitment: Array[Array[Byte]]): Boolean =
  {
    val A = commitment.map(x => cs.decodePoint(x))
    var A_sum: ECPoint = null
    val share = shares.find(_.issuerID == issuerID)
    if(share.isDefined)
    {
      val X = BigInteger.valueOf(share.get.share_a.x.toLong)

      for(i <- A.indices)
      {
        if(A_sum == null)
          A_sum = A(i).multiply(X.pow(i))
        else
          A_sum = A_sum.add(A(i).multiply(X.pow(i)))
      }

      val share_a = new BigInteger(share.get.share_a.S)
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
          commitments += Commitment(issuerID, issuerCommitments.map(cs.decodePoint(_)))
        }
        else
        {
          val share = shares.find(_.issuerID == issuerID)
          if(share.isDefined) // if committee is disqualified, its shares are already deleted from the local state of the current committee
            complains += ComplainR4(issuerID, share.get.share_a, share.get.share_b)
        }
      }
    }

    R4Data(complains.toArray)
  }

  def doRound5_1(r4Data: Seq[R4Data]): R5_1Data =
  {
    def checkComplain(complain: ComplainR4): Boolean =
    {
      val violatorsCSRCommitment = CRS_commitments.find(_.issuerID == complain.violatorID).get
      val CSR_Ok = checkOnCSR(complain.share_a, complain.share_b, violatorsCSRCommitment.csr_commitment.map(_.getEncoded(true)))

      val violatorsCommitment = commitments.find(_.issuerID == complain.violatorID).get
      val Commitment_Ok = checkCommitment(complain.violatorID, violatorsCommitment.commitment.map(_.getEncoded(true)))


      CSR_Ok && !Commitment_Ok
    }

    val violatorsShares = ArrayBuffer[(Integer, SecretShare)]()

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

    R5_1Data(violatorsShares.toArray)
  }

  def getLagrangeCoeffs(t: Integer): Array[BigInteger] =
  {
    var coeffs = new ArrayBuffer[BigInteger](t)

    for(i <- 1 to t)
    {
      var coeff = new BigDecimal("1")

      for(j <- 1 to t)
      {
        if(i != j)
          coeff = coeff.multiply(BigDecimal.valueOf(j).divide(BigDecimal.valueOf(j).subtract(BigDecimal.valueOf(i)), MathContext.DECIMAL128))
      }
      // Rounding the floating point result
      coeff = coeff.setScale(0, BigDecimal.ROUND_HALF_UP)
      coeffs += coeff.toBigInteger
    }
    coeffs.toArray
  }

  def restoreSecret(shares: ArrayBuffer[SecretShare]): BigInteger =
  {
    val sortedShares = shares.sortBy(_.x)
    val coeffs = getLagrangeCoeffs(sortedShares.last.x)

    var restoredSecret = new BigInteger("0")
    for(i <- sortedShares.indices)
    {
      var L = coeffs(sortedShares(i).x.toInt - 1)

      if(L.compareTo(BigInteger.valueOf(0)) == -1)
        L = L.add(cs.orderOfBasePoint)

      restoredSecret = restoredSecret.add(L.multiply(new BigInteger(sortedShares(i).S))).mod(cs.orderOfBasePoint)
    }
    restoredSecret
  }

  def doRound5_2(r5_1Data: Seq[R5_1Data]): SharedPublicKey =
  {
    case class ViolatorShare(violatorID: Integer, violatorShares: ArrayBuffer[SecretShare])
    val violatorsShares = new ArrayBuffer[ViolatorShare]

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
            violatorsShares += ViolatorShare(violatorID, new ArrayBuffer[SecretShare]()+= violatorShare)
        }
      }
    }

    val violatorsSecretKeys = for(i <- violatorsShares.indices) yield {
      (violatorsShares(i).violatorID, restoreSecret(violatorsShares(i).violatorShares))
    }

    val violatorsPublicKeys = for(i <- violatorsSecretKeys.indices) yield {
      (violatorsSecretKeys(i)._1, g.multiply(violatorsSecretKeys(i)._2))
    }

    var honestPublicKeysSum = A(0) // own public key
    for(i <- commitments.indices){
      honestPublicKeysSum = honestPublicKeysSum.add(commitments(i).commitment(0))
    }

    var violatorsPublicKeysSum: ECPoint = cs.infinityPoint
    for(i <- violatorsPublicKeys.indices){
      violatorsPublicKeysSum = violatorsPublicKeysSum.add(violatorsPublicKeys(i)._2)
    }

    val sharedPublicKey = honestPublicKeysSum.add(violatorsPublicKeysSum)

    sharedPublicKey.getEncoded(true)
  }
}
