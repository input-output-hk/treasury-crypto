package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.keygen.datastructures_new.round1.R1Data
import io.iohk.protocol.keygen.datastructures_new.round1.SecretShare
import io.iohk.protocol.keygen.math.Polynomial
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.util.Try

class DistrKeyGenCommittee(ctx:              CryptoContext,
                           secretKey:        PrivKey,
                           transportKeyPair: KeyPair,
                           secretSeed:       Array[Byte],
                           committee:        Identifier[Int]) extends DistrKeyGenState(ctx, committee) {
  import ctx.{blockCipher, group, hash}

  private val (poly_A, poly_B) = buildPolynomials
  private val myCommitteePubKey = transportKeyPair._2
  private val myCommitteeId = committee.getId(myCommitteePubKey).get


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
