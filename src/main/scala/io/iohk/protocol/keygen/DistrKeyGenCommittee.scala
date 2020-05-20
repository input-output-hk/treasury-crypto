package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey}
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.keygen.datastructures_new.round1.{OpenedShare, R1Data, SecretShare}
import io.iohk.protocol.keygen.math.Polynomial
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.util.Try

class DistrKeyGenCommittee(ctx:              CryptoContext,
                           secretKey:        PrivKey,
                           transportKeyPair: KeyPair,
                           secretSeed:       Array[Byte],
                           committee:        Identifier[Int]) extends DistrKeyGenState(ctx, committee) {
  import ctx.{blockCipher, group}

  private val (poly_A, poly_B) = buildPolynomials
  private[keygen] val myCommitteePubKey = transportKeyPair._2
  private[keygen] val myCommitteeId = committee.getId(myCommitteePubKey).get
  private[keygen] val myTransportPrivKey = transportKeyPair._1
  private[keygen] val myTransportPubKey = transportKeyPair._2


  def generateR1Data(): Try[R1Data] = Try {
    val E = for (i <- 0 until honestThreshold) yield {
      val g_a = g.pow(poly_A(i)).get
      val h_b = h.pow(poly_B(i)).get
      g_a.multiply(h_b).get
    }

    val otherMembers = committee.getPubKeysWithId - myCommitteeId

    val S = otherMembers.map { case (memberId, memberPubKey) =>
      val x = memberId + 1 // add 1 to memberId to avoid having (x = 0). Otherwise we will expose our secretKey.
      assert(x > 0, "x should never be 0 or less. Something is completely wrong with the member id!")
      val s_a = poly_A.evaluate(x)
      val s_b = poly_B.evaluate(x)
      val e_a = HybridEncryption.encrypt(memberPubKey, s_a.toByteArray).get
      val e_b = HybridEncryption.encrypt(memberPubKey, s_b.toByteArray).get
      SecretShare(memberId, e_a) -> SecretShare(memberId, e_b)
    }.toVector

    R1Data(myCommitteeId, E.toVector, S.map(_._1), S.map(_._2))
  }

  /**
    * Verify shares that have been sent to this member by the other committee member who generated r1Data
    * It is assumed that r1Data has already been verifier with general checks by DistrKeyGenState.verifyR1Data()
    * @return Some(_) if valid shares for the current committee member were found, otherwise None
    */
  def extractAndVerifyPersonalR1Shares(r1Data: R1Data): Option[(OpenedShare, OpenedShare)] = {
    val share_a = r1Data.S_a.find(_.receiverID == myCommitteeId)
    val share_b = r1Data.S_b.find(_.receiverID == myCommitteeId)
    if (share_a.isEmpty || share_b.isEmpty)
      throw new IllegalArgumentException("Invalid r1Data! There is no share for the committee member #" + myCommitteeId) // there might be some problems with the code, r1Data had to be pre-verified

    val openedShare_a = OpenedShare(share_a.get.receiverID, HybridEncryption.decrypt(myTransportPrivKey, share_a.get.S).get)
    val openedShare_b = OpenedShare(share_b.get.receiverID, HybridEncryption.decrypt(myTransportPrivKey, share_b.get.S).get)

    verifyR1Shares(openedShare_a, openedShare_b, r1Data.E) match {
      case true => Some(openedShare_a -> openedShare_b)
      case false => None
    }
  }

  /**
    * Generate coefficients for two polynomials "a(x)" and "b(x)" of degree t-1, where t is the minimal threshold
    * for the number of honest participants
    * A free coefficient of "a(x)" is set to be the secretKey, all others are randomly generated from the secretSeed.
    */
  private def buildPolynomials: (Polynomial, Polynomial) = {
    val drng = new FieldElementSP800DRNG(secretSeed ++ "Polynomials".getBytes, group.groupOrder)
    val poly_a = new Polynomial(ctx, honestThreshold-1, secretKey, drng)      // for the (t,n)-threshold protocol we should set up polynomials of degree t-1
    val poly_b = new Polynomial(ctx, honestThreshold-1, drng.nextRand, drng)
    poly_a -> poly_b
  }
}
