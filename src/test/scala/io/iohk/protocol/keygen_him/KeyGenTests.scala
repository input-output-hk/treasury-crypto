package io.iohk.protocol.keygen_him

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.datastructures.Share
import io.iohk.protocol.common.him.HIM
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.secret_sharing.ShamirSecretSharing.{IdPointMap, SharingParameters, decryptShares, encryptShares, getShares, reconstructSecret}
import io.iohk.protocol.common.utils.Serialization.serializationIsCorrect
import io.iohk.protocol.keygen_him.datastructures.{R1DataSerializer, R2Data, R2DataSerializer, R3DataSerializer, R4DataSerializer}
import org.scalatest.FunSuite

import scala.util.{Random, Try}

class KeyGenTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val g = context.group.groupGenerator

  import context.group

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  def corruptR2Data(r2Data: Seq[R2Data], numOfPartiesToCorrupt: Int): Seq[R2Data] = {
    assert(numOfPartiesToCorrupt <= r2Data.length)
    r2Data.zipWithIndex.map{
      case (d, i) =>
        if (i < numOfPartiesToCorrupt){
          R2Data(
            d.senderID,
            d.coeffsCommitments.drop(1) // removing the R2-commitment of a_0 coefficient for a specified party
          )
        } else { d }
    }
  }

  def initialize(generatorsNum: Int): (Seq[DKGenerator], Int, Seq[KeyPair], Seq[BigInt], Seq[BigInt]) = {
    // The number of generated Global Public Keys is (n - t);
    // For adversarial threshold t = n/2 - 1 the (n/2 + 1) GPKs can be generated
    val generatedKeysNum = generatorsNum / 2 + 1
    val adversariesMaxNum = generatorsNum / 2 - 1

    val generatorsKeys = generateKeys(generatorsNum)
    val alphas = (0 until generatorsNum)   .map(_ => group.createRandomNumber)
    val betas  = (0 until generatedKeysNum).map(_ => group.createRandomNumber)

    val generators = generatorsKeys.map(keyPair =>
      DKGenerator(
        context,
        Seq(crs),
        keyPair,
        generatorsKeys.map(_._2),
        alphas,
        betas
      )
    )
    (generators, adversariesMaxNum, generatorsKeys, alphas, betas)
  }

  def validateGlobalPublicKeys(gpks: Seq[Seq[GroupElement]], generators: Seq[DKGenerator], alphas: Seq[BigInt], betas: Seq[BigInt]): Try[Unit] = Try {
    // All parties have the same ordered set of Global Public Keys
    assert(gpks.forall(_ == gpks.head))

    // Reconstructing the Global Secret Keys (generated via HIM multiplication) by shares from all parties
    val sharesPerGSK = generators.map(
      g => g.getPartialSKs.map(Share(IdPointMap.toPoint(g.ownID), _)) // each party has a share per GSK; all it's shares are in the same point
    ).transpose // now each row contains a set of all shares per corresponding GSK
    val gsks_reconstructed = sharesPerGSK.map(reconstructSecret(context, _))

    // Check that the reconstructed GSKs are the same as the GSKs computed directly from partial SKs via HIM multiplication
    val him = HIM(alphas, betas)
    val gsks = him.mul(generators.sortBy(_.ownID).map(_.partialSK)) // Partial SKs should be ordered by parties IDs
    assert(gsks_reconstructed == gsks)

    // Check that the public keys built from reconstructed GSKs are the same as the generated GPKs
    val gpks_reconstructed = gsks_reconstructed.map(g.pow(_).get) // GPK = g^GSK
    assert(gpks_reconstructed == gpks.head)
  }

  test("DKG_HIM_shares_encryption"){

    val partiesNum = Random.nextInt(20) + 20
    val allPartiesKeys = generateKeys(partiesNum)

    val params = SharingParameters(allPartiesKeys.map(_._2))
    val secret = context.group.createRandomNumber
    val polynomial = Polynomial(context.group, params.t - 1, secret)

    val shares = getShares(polynomial, params.allIds.map(IdPointMap.toPoint))
    val encShares = encryptShares(context, shares, params).map(_._1)

    val openedShares = allPartiesKeys.map{
      keyPair =>
        val (privKey, pubKey) = keyPair
        val receiverID = params.keyToIdMap.getId(pubKey).get

        val secretSharesForId = encShares.filter(_.receiverID == receiverID)
        val openedSharesForId = decryptShares(context, secretSharesForId, privKey)

        assert(openedSharesForId.isSuccess && openedSharesForId.get.size == 1)

        val openedShare = openedSharesForId.get.head
        assert(shares.contains(openedShare))

        openedShare
    }

    assert(openedShares.size == shares.size)
    assert(reconstructSecret(context, openedShares.take(params.t)) == secret)
  }

  test("DKG_HIM_serialization"){
    val generatorsNum = 4
    val (generators, adversariesMaxNum, _, _, _) = initialize(generatorsNum)

    val r1Data = generators.map(_.round1())
    val r2Data = generators.map(_.round2(r1Data))
    val r3Data = generators.flatMap(_.round3(corruptR2Data(r2Data, adversariesMaxNum)))
    val r4Data = generators.map(_.round4(r3Data))

    // Serialization tests (will pass only with 'plainS = None' in SecretShares)
    assert(serializationIsCorrect(r1Data, R1DataSerializer))
    assert(serializationIsCorrect(r2Data, R2DataSerializer))
    assert(r3Data.nonEmpty && serializationIsCorrect(r3Data, R3DataSerializer))
    assert(serializationIsCorrect(r4Data, R4DataSerializer))
  }

  test("DKG_HIM_correct_run"){
    val generatorsNum = 10
    val (generators, _, _, alphas, betas) = initialize(generatorsNum)

    val r1Data = generators.map(_.round1())
    val r2Data = generators.map(_.round2(r1Data))
    val r3Data = generators.flatMap(_.round3(r2Data))
    // The protocol is running without any deviations so there shouldn't be any complaints
    assert(r3Data.isEmpty)
    // Get Global Public Keys (all g^partialSK's multiplied by HIM)
    val r4Data = generators.map(_.round4(r3Data))
    assert(validateGlobalPublicKeys(r4Data.map(_.globalPubKeys), generators, alphas, betas).isSuccess)
  }

  test("DKG_HIM_misbehaving_parties_run"){
    val generatorsNum = 10
    val (generators, adversariesMaxNum, _, alphas, betas) = initialize(generatorsNum)

    val r1Data = generators.map(_.round1())
    val r2Data = generators.map(_.round2(r1Data))
    val r3Data = generators.flatMap(_.round3(corruptR2Data(r2Data, adversariesMaxNum)))
    // There should be complaints on corrupted parties
    assert(r3Data.nonEmpty)
    // Get Global Public Keys (all g^partialSK's multiplied by HIM)
    val r4Data = generators.map(_.round4(r3Data))
    assert(validateGlobalPublicKeys(r4Data.map(_.globalPubKeys), generators, alphas, betas).isSuccess)
  }
}
