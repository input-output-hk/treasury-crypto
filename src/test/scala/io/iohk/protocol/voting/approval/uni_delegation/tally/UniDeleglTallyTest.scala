package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.protocol.keygen.{DistrKeyGen, RoundsData}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.{DelegatedUniDelegVote, DirectUniDelegVote, UniDelegExpertBallot, UniDelegPublicStakeBallot}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

class UniDelegTallyTest extends FunSuite with UniDelegTallyTestSetup {

}

object UniDelegTallyTest {

  def generateCommitteeKeys(committeeSize: Int)(implicit group: DiscreteLogGroup): Seq[KeyPair] = {
    for (i <- 0 until committeeSize) yield {
      val privKey = group.createRandomNumber
      (privKey -> group.groupGenerator.pow(privKey).get)
    }
  }
}

trait UniDelegTallyTestSetup {
  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))

  import ctx.group

  val numberOfExperts = 5
  val numberOfVoters = 10
  val stake = 2
  val numberOfProposals = 10
  val numberOfChoices = 3
  val voterChoices = List.fill[Int](numberOfProposals)(1)
  val expertChoices = List.fill[Int](numberOfProposals)(2)
  val pctx = new ApprovalContext(ctx, numberOfChoices, numberOfExperts, numberOfProposals)

  val committeeKeys = UniDelegTallyTest.generateCommitteeKeys(5)
  val cmIdentifier = new CommitteeIdentifier(committeeKeys.map(_._2))
  val sharedVotingKey = committeeKeys.foldLeft(group.groupIdentity)((acc, key) => acc.multiply(key._2).get)

  val summator = new UniDelegBallotsSummator(pctx)
  for (i <- 0 until numberOfVoters) {
      summator.addVoterBallot(
        UniDelegPublicStakeBallot.createBallot(pctx, DirectUniDelegVote(voterChoices), sharedVotingKey, stake).get)
      summator.addVoterBallot(
        UniDelegPublicStakeBallot.createBallot(pctx, DelegatedUniDelegVote(0), sharedVotingKey, stake).get)
    }
  val expertBallots = for (i <- 0 until numberOfExperts) yield
    UniDelegExpertBallot.createBallot(pctx, i, DirectUniDelegVote(expertChoices), sharedVotingKey).get

  val dkgR1DataAll = committeeKeys.map { keys =>
    val dkg = new DistrKeyGen(ctx, keys, keys._1, keys._1.toByteArray, committeeKeys.map(_._2), cmIdentifier, RoundsData())
    dkg.doRound1().get
  }
}
