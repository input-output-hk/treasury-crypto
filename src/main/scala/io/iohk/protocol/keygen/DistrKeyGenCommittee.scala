package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.math.Polynomial
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.util.Try

class DistrKeyGenCommittee(ctx:                 CryptoContext,
                           secretKey:           PrivKey,
                           transportKeyPair:    KeyPair,
                           secretSeed:          Array[Byte],
                           committeeIdentifier: Identifier[Int]) extends DistrKeyGenState(ctx, committeeIdentifier) {
  import ctx.{blockCipher, group, hash}

  private val (poly_A, poly_B) = buildPolynomials


  def generateR1Data(): Try[R1Data] = Try {
    val E = for (i <- 0 until tolerableThreshold) yield {
      val g_a = g.pow(poly_A(i)).get
      val h_b = h.pow(poly_B(i)).get
      g_a.multiply(h_b).get
    }

    ???
  }


  /**
    * Generate coefficients for two polynomials "a(x)" and "b(x)" of degree t-1, where t is the minimal threshold
    * for the number of honest participants
    * A free coefficient of "a(x)" is set to be the secretKey, all others are randomly generated from the secretSeed.
    */
  private def buildPolynomials: (Polynomial, Polynomial) = {
    val drng = new FieldElementSP800DRNG(secretSeed ++ "Polynomials".getBytes, group.groupOrder)
    val poly_a = new Polynomial(ctx, tolerableThreshold-1, secretKey, drng)      // for the (t,n)-threshold protocol we should set up polynomials of degree t-1
    val poly_b = new Polynomial(ctx, tolerableThreshold-1, drng.nextRand, drng)
    poly_a -> poly_b
  }
}
