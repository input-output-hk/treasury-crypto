package io.iohk.protocol.resharing

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.datastructures.Share
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.secret_sharing.ShamirSecretSharing.{IdPointMap, SharingParameters, getShares, reconstructSecret}
import io.iohk.protocol.common.utils.Serialization.serializationIsCorrect
import io.iohk.protocol.resharing.datastructures.{ResharingComplaintsSerializer, ResharingData, ResharingDataSerializer, SharedShare}
import org.scalatest.FunSuite

class ResharingTests extends FunSuite {

  private val context = new CryptoContext(None)
  import context.group

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  def corruptResharings(resharings: Seq[ResharingData], numOfPartiesToCorrupt: Int): Seq[ResharingData] = {
    assert(numOfPartiesToCorrupt <= resharings.length)
    resharings.zipWithIndex.map{
      case (d, i) =>
        if (i < numOfPartiesToCorrupt){
          // Removing the commitment of a_0 coefficient in each SharedShare of a current party
          ResharingData(
            d.senderID,
            d.sharedShares.map(s => SharedShare(s.encShares, s.coeffsCommitments.drop(1)))
          )
        } else { d }
    }
  }

  def initialize(partiesNum: Int): (Seq[Resharing], Int, Seq[KeyPair], SharingParameters) = {
    val adversariesMaxNum = partiesNum / 2 - 1

    val allPartiesKeys = generateKeys(partiesNum)
    val allPartiesPubKeys = allPartiesKeys.map(_._2)
    val params = SharingParameters(allPartiesPubKeys)

    val receivingParties = allPartiesKeys.map(keyPair => Resharing(context, keyPair, allPartiesPubKeys))

    (receivingParties, adversariesMaxNum, allPartiesKeys, params)
  }

  def getSharesPerParty(secrets: Seq[BigInt], params: SharingParameters): Seq[Seq[Share]] = {
    // Initial shares of the secrets
    val sharesPerSecret = secrets.map{ secret =>
      val polynomial = Polynomial(context.group, params.t - 1, secret)
      // Creating a set of shares per secret
      // NOTE: the resharing parties can have arbitrary IDs (i.e. different from the the receiving parties' IDs) so just using the range: (0 until partiesNum)
      getShares(polynomial, (0 until params.n).map(IdPointMap.toPoint))
    }
    // Transposing to get shares of all secrets per party
    sharesPerSecret.transpose
  }

  def reshareSharesOfTheParty(partyShares: Seq[Share], params: SharingParameters): ResharingData = {
    // Checking that all shares belong to the same party
    assert(partyShares.forall(_.point == partyShares.head.point))
    // ID of the party (dealer relatively to the receiving parties) who shares the current share
    val dealerID = IdPointMap.toId(partyShares.head.point)
    // Party gets a set of shares per each owned share
    Resharing.getResharings(context, params, dealerID, partyShares.map(_.value))
  }

  def testResharing(withCorruptions: Boolean): Unit = {
    val partiesNum = 10 // assuming that the number of resharing parties is the same as the number of receiving parties
    val (receivers, adversariesMaxNum, _, params) = initialize(partiesNum)
    val secretsNum = partiesNum - adversariesMaxNum // according to the HIM DKG the number of generated secrets available for usage is (n - t)

    val secrets = (0 until secretsNum).indices.map(_ => context.group.createRandomNumber)
    // Getting set of shares (one share per each secret) for each resharing party
    val shares = getSharesPerParty(secrets, params)

    // Simulating resharing of the secrets by sharing the initial shares owned by corresponding resharing virtual parties;
    val resharings = shares.map(reshareSharesOfTheParty(_, params))

    // Receiving parties receive and validate the resharings and create complaints if needed
    val complaints = receivers.flatMap(_.receiveResharings(
      if(withCorruptions) corruptResharings(resharings, adversariesMaxNum)
      else resharings
    ))

    assert(
      if(withCorruptions) complaints.nonEmpty
      else complaints.isEmpty
    )

    // Getting new shares per receiving party
    val newShares = receivers.map(_.buildNewShares(complaints))
    assert(
      // Transposing to get shares of all parties per secret
      newShares.transpose.zip(secrets).forall{case (sharesPerSecret, secret) =>
        reconstructSecret(context, sharesPerSecret.take(params.t)) == secret &&
        // Using a full set of shares to check that all new shares are consistent
        reconstructSecret(context, sharesPerSecret) == secret
      }
    )
  }

  test("resharing"){
    testResharing(withCorruptions = false)
  }

  test("resharing_with_corruptions"){
    testResharing(withCorruptions = true)
  }

  test("serialization"){
    val partiesNum = 4
    val (receivers, adversariesMaxNum, _, params) = initialize(partiesNum)
    val secretsNum = partiesNum - adversariesMaxNum

    val secrets = (0 until secretsNum).indices.map(_ => group.createRandomNumber)
    val shares = getSharesPerParty(secrets, params)

    val resharings = shares.map(reshareSharesOfTheParty(_, params))
    val complaints = receivers.flatMap(_.receiveResharings(corruptResharings(resharings, adversariesMaxNum)))

    assert(serializationIsCorrect(resharings, ResharingDataSerializer))
    assert(complaints.nonEmpty && serializationIsCorrect(complaints, ResharingComplaintsSerializer))
  }
}
