package io.iohk.protocol.keygen_2_0.NIZKs.rnce

import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.CorrectSharesDecryption.{Witness, decryptionCommitment}
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}
import io.iohk.protocol.keygen_2_0.utils.DlogGroupArithmetics.exp
import org.scalatest.FunSuite

class CorrectSharesDecryptionTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group

  private val rnce_crs = RnceCrsLight(g1 = dlogGroup.createRandomGroupElement.get, g2 = dlogGroup.createRandomGroupElement.get)
  private val cs_crs = CorrectSharesDecryption.CRS(rnce_crs, dlogGroup.createRandomGroupElement.get, dlogGroup.createRandomGroupElement.get)

  import context.group

  test("decryptionCommitment"){

    val (sk, pk) = RnceBatchedEncryption.keygen(RnceParams(rnce_crs))

    val share = group.createRandomNumber
    val shareEnc = RnceBatchedEncryption.encrypt(pk, share, rnce_crs).get._1

    // check that reconstructed value inside of the commitment is the same as initially encrypted value
    // don't mask the value inside of the commitment with powers of h
    val decrComm = decryptionCommitment(
      ct = shareEnc,
      sk = sk,
      h  = group.createRandomGroupElement.get, // no matter what element is here due to it will be zero-exponentiated
      ds = Array.fill(sk.secretKeys.length)(BigInt(0))) // zero exponents for h

    assert(decrComm == exp(rnce_crs.g1, share))
  }

  test("CorrectSharesDecryption"){

    val n = 10
    // The same keypair is used for encryption of shares and shares_
    val (sk, pk) = RnceBatchedEncryption.keygen(RnceParams(rnce_crs))

    val gammas = (0 until n).map(_ => group.createRandomNumber) // simulates values of shares multipliers

    val shares = (0 until n).map(_ => group.createRandomNumber) // simulated values of shares
    val sharesEnc = shares.map(s => RnceBatchedEncryption.encrypt(pk, s, rnce_crs).get._1) // encrypted shares on PK of receiver
    val sharesSum = shares.zip(gammas).foldLeft(BigInt(0)){case (sum, (s, g)) => (sum + s * g).mod(group.groupOrder)} // sum of decrypted shares

    val shares_ = (0 until n).map(_ => group.createRandomNumber) // simulated values of shares_
    val sharesEnc_ = shares_.map(s => RnceBatchedEncryption.encrypt(pk, s, rnce_crs).get._1) // encrypted shares_ on PK of receiver
    val sharesSum_ = shares_.zip(gammas).foldLeft(BigInt(0)){case (sum, (s, g)) => (sum + s * g).mod(group.groupOrder)} // sum of decrypted shares_

    val lambda = group.createRandomNumber // Hash(Delta_0, Delta_1, ... Delta_t)
    val statement = CorrectSharesDecryption.Statement(
      sharesEnc,
      sharesEnc_,
      lambda,
      gammas
    )

    val proof = CorrectSharesDecryption(cs_crs, statement, group).prove(Witness(sharesSum, sharesSum_, sk))
    assert(CorrectSharesDecryption(cs_crs, statement, group).verify(proof, pk))
  }
}
