package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.keygen_2_0.datastructures.{HoldersOutput, SecretShareSerializer}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.NIZKs.rnce.{CorrectSharesDecryption, CorrectSharesEncryption}
import io.iohk.protocol.keygen_2_0.math.LagrangeInterpolation
import io.iohk.protocol.keygen_2_0.rnce_encryption.RnceKeyPair
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.RnceParams
import org.scalatest.FunSuite

import scala.util.Random

case class Node(context:    CryptoContext,
                rnceParams: RnceParams,
                proofsCrs: (CorrectSharesEncryption.CRS, CorrectSharesDecryption.CRS),
                stake:      Int = Random.nextInt(20) + 1, // affects committee size as well as nominatorsThreshold
                id:         Int = Random.nextInt()) {

  private val longTermKeyPair = encryption.createKeyPair(context.group).get
  val longTermPubKey : PubKey = longTermKeyPair._2

  var nominatorOpt : Option[Nominator] = None
  var holderOpt : Option[Holder] = None

  def setNominator(params: NominationParameters) : Unit = {
    nominatorOpt = Nominator.create(context, rnceParams, longTermKeyPair, stake, params.thresholdCoeff, params.seed, params.longTermPubKeys)
  }

  def setHolder(nominations : Seq[Nomination]) : Unit = {
    holderOpt = Holder.create(context, rnceParams, proofsCrs, longTermKeyPair, nominations)
  }

  def copy(): Node = {
    Node(context, rnceParams, proofsCrs, stake, id)
  }
}

case class NominationParameters(seed: BigInt,
                                thresholdCoeff: BigInt,
                                longTermPubKeys: Seq[PubKey])

case class EpochContext(allNodes: Seq[Node] = Seq(),
                        nominations: Seq[Nomination] = Seq(),
                        holdersOutputs: Seq[HoldersOutput] = Seq())

class KeyGenTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  // Rnce parameters
  import context.group
  // Random generators
  private val (g1, g2, g3, g4) = (CryptoContext.generateRandomCRS, CryptoContext.generateRandomCRS, CryptoContext.generateRandomCRS, CryptoContext.generateRandomCRS)
  private val rnce_params = RnceParams(
    RnceCrsLight(g1, g2)
  )
  private val proofs_crs = (
    CorrectSharesEncryption.CRS(rnce_params.crs, g3),
    CorrectSharesDecryption.CRS(rnce_params.crs, g3, g4)
  )


  private val nodesNum = 10 //20
  private val epochsNum = 3 //8
  // defines a nominating committee size (a well as a holding committee size)
  private val nominatorsThreshold = BigInt("08ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

  def initializeParticipants(nodes: Seq[Node] = Seq()): Seq[Node] ={
    if(nodes.isEmpty){    // create nodes for the initial epoch
      for (_ <- 0 until nodesNum) yield {
        Node(context, rnce_params, proofs_crs)
      }
    } else {              // re-initialize existing nodes
      nodes.map(_.copy())
    }
  }

  def setNominatingCommittee(allNodes: Seq[Node], params: NominationParameters): Seq[Node] = {
    allNodes.foreach(_.setNominator(params))
    allNodes.filter(_.nominatorOpt.nonEmpty)
  }

  def selectHoldingCommittee(nominators: Seq[Node]): Seq[Nomination] = {
    nominators.map(_.nominatorOpt.get.selectHolder())
  }

  // Nominating each Node as a Holder directly without Nominators
  def setNominations(longTermPubKeys: Seq[PubKey]): Seq[Nomination] = {
    longTermPubKeys.map(Nomination.create(context, rnce_params, _))
  }

  def setHoldingCommittee(allNodes: Seq[Node], nominations: Seq[Nomination]): Seq[Node] = {
    allNodes.foreach(_.setHolder(nominations))
    allNodes.filter(_.holderOpt.nonEmpty)
  }

  def generate(holders: Seq[Node], nominationsNext: Seq[Nomination]): Seq[HoldersOutput] = {
    holders.flatMap(_.holderOpt.get.generate(nominationsNext))
  }

  def reshare(holders: Seq[Node], prevHoldersOutputs: Seq[HoldersOutput], nominationsNext: Seq[Nomination]): Seq[HoldersOutput] ={
    holders.flatMap(_.holderOpt.get.reshare(prevHoldersOutputs, nominationsNext))
  }

  // Returns (common_sk1, common_sk2), where common_sk1 = sum(sk1_i), common_sk2 = sum(sk2_i)
  def getCommonSecret(holders: Seq[Node]): (BigInt, BigInt) = {
    holders.foldLeft((BigInt(0), BigInt(0))){
      (sum, node) =>
        val partialSum = node.holderOpt.get.partialSecretsInitial
          .foldLeft((BigInt(0), BigInt(0)))((sum, ps) => (sum._1 + ps._1, sum._2 + ps._2))
        (
          (sum._1 + partialSum._1).mod(context.group.groupOrder),
          (sum._2 + partialSum._2).mod(context.group.groupOrder)
        )
    }
  }
  // Returns (common_sk1, common_sk2) reconstructed from their outputs
  def reconstructCommonSecret(holders: Seq[Node]): (BigInt, BigInt) = {
    val all_shares1 = holders.flatMap(_.holderOpt.get.combinedShares1)
    val all_shares2 = holders.flatMap(_.holderOpt.get.combinedShares2)

    require(all_shares1.length == all_shares2.length)
    val t = all_shares1.length / 2 + 1

    (LagrangeInterpolation.restoreSecret(context.group, all_shares1, t), // common_sk1
     LagrangeInterpolation.restoreSecret(context.group, all_shares2, t)) // common_sk2
  }

  def generateKeys(num: Int) : Seq[RnceKeyPair] =
    for (_ <- 0 until num) yield rnce_encryption.createRnceKeyPair(rnce_params).get

  test("sharing"){

    val testsNum = 10

    for(_ <- 0 until testsNum){
      val holdingMembersNum = Random.nextInt(20) + 20
      val secret = BigInt(Random.nextInt().abs)

      val holdingCommitteeKeys = generateKeys(holdingMembersNum)
      val holdingCommitteeParams = SharingParameters(holdingCommitteeKeys.map(_._2))

      val shares = Holder.shareSecret(context, 0, secret, holdingCommitteeParams)
      assert(Holder.reconstructSecret(context, shares._1) == secret)
    }
  }

  test("shares_encryption"){

    val holdingMembersNum = Random.nextInt(20) + 20
    val holdingCommitteeKeys = generateKeys(holdingMembersNum)
    val holdingCommitteeParams = SharingParameters(holdingCommitteeKeys.map(_._2))

    val secret = BigInt(Random.nextInt().abs)
    val shares = Holder.shareSecret(context, 0, secret, holdingCommitteeParams)

    val holdingKeyIdMap = holdingCommitteeParams.keyToIdMap
    val allSecretShares = Holder.encryptShares(context, rnce_params, shares._1, holdingKeyIdMap)

    holdingCommitteeKeys.foreach{
      keyPair =>
        val (privKey, pubKey) = keyPair
        val receiverID = holdingKeyIdMap.getId(pubKey).get

        val secretSharesForId = allSecretShares.map(_._1).filter(_.receiverID == receiverID)
        val openedSharesForId = Holder.decryptShares(context, rnce_params, secretSharesForId, privKey)

        assert(openedSharesForId.isSuccess)

        openedSharesForId.get.foreach{
          openedShare =>
            assert(shares._1.contains(openedShare))
        }
    }
  }

  test("secret_shares_serialization"){
    val holdingMembersNum = Random.nextInt(20) + 20
    val holdingCommitteeKeys = generateKeys(holdingMembersNum)
    val holdingCommitteeParams = SharingParameters(holdingCommitteeKeys.map(_._2))

    val secret = BigInt(Random.nextInt().abs)
    val shares = Holder.shareSecret(context, 0, secret, holdingCommitteeParams)

    val holdingKeyIdMap = holdingCommitteeParams.keyToIdMap
    val allSecretShares = Holder.encryptShares(context, rnce_params, shares._1, holdingKeyIdMap)

    allSecretShares.map(_._1).foreach{ s =>
      val s_restored = SecretShareSerializer.parseBytes(s.bytes, Some(context.group)).get
      require(s_restored.equals(s))
    }
  }

  test("protocol"){

    var prevEpoch = EpochContext()
    var commonSecret: Option[(BigInt, BigInt)] = None

    for (epoch <- 0 until epochsNum){

      val allNodes = initializeParticipants(prevEpoch.allNodes)

      if(epoch > 0){
        // Long-term keys of the same nodes should be re-generated for each epoch
        assert(allNodes.map(_.id) == prevEpoch.allNodes.map(_.id) &&
               allNodes.map(_.longTermPubKey) != prevEpoch.allNodes.map(_.longTermPubKey))
      }

      // epoch-related values
      val nominationParams = NominationParameters(
        seed = Random.nextInt(),
        thresholdCoeff = nominatorsThreshold,
        longTermPubKeys = allNodes.map(_.longTermPubKey)
      )

      val nominators = setNominatingCommittee(allNodes, nominationParams)
      val nominations = selectHoldingCommittee(nominators) // nominations for next epoch

      // Holders for current epoch, i.e. Nodes nominated in previous epoch
      val holders = setHoldingCommittee(prevEpoch.allNodes, prevEpoch.nominations)
      // Shares from pre-previous epoch holders which should be reshared by previous epoch holders
      val old_shares = prevEpoch.holdersOutputs

      // Printing sharing parameters for the current epoch
      // Holders will share/reshare their secrets for the next epoch nominated holders
      println(s"${epoch}: n = ${nominations.size}, t = ${nominations.size / 2 + 1};")

      val new_shares =
        epoch match {
          case 0 => Seq()
          case 1 => generate(holders, nominations)
          case _ => reshare(holders, old_shares, nominations)
        }

      if(epoch > 0){
        // New shares should be created during active protocol phases
        assert(new_shares.nonEmpty)
      }
      // Validate outputs
      epoch match {
        case 0 =>
        case 1 => commonSecret = Some(getCommonSecret(holders))
        case _ => assert(commonSecret.get == reconstructCommonSecret(holders))
      }
      prevEpoch = EpochContext(allNodes, nominations, new_shares)
    }
  }

  test("performance"){
    import io.iohk.core.utils.TimeUtils

    var prevEpoch = EpochContext()
    var commonSecret: Option[(BigInt, BigInt)] = None

    for (epoch <- 0 until epochsNum){

      val allNodes = initializeParticipants(prevEpoch.allNodes)
      val allLongTermPubKeys = allNodes.map(_.longTermPubKey)

      // Nominators selection phase is removed to make size of holding committee constant
      val nominations = setNominations(allLongTermPubKeys) // one nomination per Node

      // Holders for current epoch, i.e. Nodes nominated in previous epoch
      val holders = setHoldingCommittee(prevEpoch.allNodes, prevEpoch.nominations)
      // Shares from pre-previous epoch holders which should be reshared by previous epoch holders
      val old_shares = prevEpoch.holdersOutputs

      println(s"${epoch}: n = ${holders.size}, t = ${holders.size / 2 + 1};")

      // Current epoch contains the same number of nominated members as a previous one, so the committee size is constant
      if (holders.nonEmpty){
        assert(nominations.length == holders.length)
      }

      val new_shares =
        epoch match {
          case 0 => Seq()
          case 1 => {
            TimeUtils.get_time_average_s(
              "generate:",
              generate(holders, nominations),
              holders.length
            )._1
          }
          case _ => {
            TimeUtils.get_time_average_s(
              "reshare:",
              reshare(holders, old_shares, nominations),
              holders.length
            )._1
          }
        }

      val totalTraffic = new_shares.foldLeft(0)((sum, output) => sum + output.size)
      println(s"Total traffic: ${totalTraffic/(1024)} KB")
//      println(s"; Total size = ${
//        new_shares.foldLeft(0)((sum, output) => {
//          print(output.size + " "); sum + output.size
//        })
//      }")

      // Verifying correctness of the generated outputs
      if(epoch > 0){
        assert(new_shares.nonEmpty)
      }
      epoch match {
        case 0 =>
        case 1 => commonSecret = Some(getCommonSecret(holders))
        case _ => assert(commonSecret.get == reconstructCommonSecret(holders))
      }
      prevEpoch = EpochContext(allNodes, nominations, new_shares)
    }
  }
}
