//package io.iohk.protocol.integration
//
//import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
//import io.iohk.protocol.{CommitteeIdentifier, CryptoContext, Identifier}
//import io.iohk.protocol.keygen.CommitteeMember
//import io.iohk.protocol.keygen.datastructures.round1.R1Data
//import io.iohk.protocol.voting.approval.ApprovalContext
//import io.iohk.protocol.voting.approval.multi_delegation.tally.{MultiDelegBallotsSummator, MultiDelegTally}
//import io.iohk.protocol.voting.approval.multi_delegation.{DelegatedMultiDelegVote, DirectMultiDelegVote, MultiDelegExpertBallot, MultiDelegPrivateStakeBallot, MultiDelegPublicStakeBallot, MultiDelegVoterBallot}
//
//import scala.util.Try
//
//abstract class MultiDelegVoting(ctx: CryptoContext) extends Elections[MultiDelegVoterBallot,
//                                                                      MultiDelegExpertBallot,
//                                                                      ApprovalContext,
//                                                                      Map[Int, Vector[BigInt]]] {
//
//  override def runTally(committee: Identifier[_],
//                        dkgViolators: Map[PubKey, Option[PrivKey]],
//                        voterBallots: Seq[MultiDelegVoterBallot],
//                        expertBallots: Seq[MultiDelegExpertBallot],
//                        dkgR1DataAll: Seq[R1Data]): Try[Map[Int, Vector[BigInt]]] = Try {
//
//    val pctx = new ApprovalContext(ctx,3, 3, 5)
//    val summator = new MultiDelegBallotsSummator(pctx)
//
//    voterBallots.foreach(summator.addVoterBallot(_).get)
//
//    val tally = new MultiDelegTally(ctx, committee, dkgViolators)
//
//    // let's simulate 1 failed CM at each round
//    val r1DataAll = committeeMembers.drop(1).map(_.doTallyR1(voterBallots).get)
//    val r2DataAll = committeeMembers.drop(2).map(_.doTallyR2(r1DataAll, dkgR1DataAll).get)
//    val r3DataAll = committeeMembers.drop(3).map(_.doTallyR3(r2DataAll, dkgR1DataAll, expertBallots).get)
//    val r4DataAll = committeeMembers.drop(4).map(_.doTallyR4(r3DataAll, dkgR1DataAll).get)
//    committeeMembers.drop(4).foreach(_.finalizeTally(r4DataAll, dkgR1DataAll).get)
//
//    val result = committeeMembers.last.getTallyResult.get
//    committeeMembers.drop(4).foreach(c => require(c.getTallyResult.get == result))
//    result
//  }
//}
//
//class MultiDelegVotingScenario1(ctx: CryptoContext) extends MultiDelegVoting(ctx) {
//  private val proposalID = 1
//  private val votersNum = 2
//  private val numberOfExperts = 2
//  val pctx = new ApprovalContext(ctx, 3, numberOfExperts)
//
//  def getContext = pctx
//
//  override def runVoting(sharedPubKey: PubKey): (Seq[MultiDelegPublicStakeBallot], Seq[MultiDelegExpertBallot]) = {
//    val votersBallots =
//      for (_ <- 0 until votersNum) yield
//        MultiDelegPublicStakeBallot.createBallot(pctx, proposalID, DelegatedMultiDelegVote(1), sharedPubKey, 3, false).get
//
//    val expertsBallots =
//      for (expertId <- 0 until numberOfExperts) yield
//        MultiDelegExpertBallot.createBallot(pctx, proposalID, expertId, DirectMultiDelegVote(0), sharedPubKey, false).get
//
//    votersBallots -> expertsBallots
//  }
//
//  override def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = {
//    if (tallyRes.size == 1) {
//      tallyRes(proposalID)(0) == 6 &&
//        tallyRes(proposalID)(1) == 0 &&
//        tallyRes(proposalID)(2) == 0
//    } else false
//  }
//}
//
//class MultiDelegVotingScenario2(ctx: CryptoContext) extends MultiDelegVoting(ctx) {
//
//  val proposalIDs = Set(4, 11)
//  val votersNum = 10
//  val votersDelegatedNum = 20
//  val numberOfExperts = 5
//  val pctx = new ApprovalContext(ctx, 3, numberOfExperts)
//
//  def getContext = pctx
//
//  def runVoting(sharedPubKey: PubKey): (Seq[MultiDelegVoterBallot], Seq[MultiDelegExpertBallot]) =
//  {
//    proposalIDs.foldLeft((Seq[MultiDelegPublicStakeBallot](), Seq[MultiDelegExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
//      val votersBallots =
//        for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
//          val vote = if (voterId % 2 == 1) DirectMultiDelegVote(0) else DirectMultiDelegVote(2)
//          MultiDelegPublicStakeBallot.createBallot(pctx, proposalID, vote, sharedPubKey, stake = proposalID, false).get
//        }
//
//      val votersDelegatedBallots =
//        for (_ <- 0 until votersDelegatedNum) yield
//          MultiDelegPublicStakeBallot.createBallot(pctx, proposalID, DelegatedMultiDelegVote(0), sharedPubKey, stake = proposalID, false).get
//
//      val expertsBallots =
//        for (expertId <- 0 until numberOfExperts) yield
//          MultiDelegExpertBallot.createBallot(pctx, proposalID, expertId, DirectMultiDelegVote(1), sharedPubKey,false).get
//
//      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
//    }
//  }
//
//  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = Try {
//    require(tallyRes.size == 2)
//    proposalIDs.foreach { id =>
//      require(tallyRes(id)(0) == 5 * id)
//      require(tallyRes(id)(1) == 20 * id)
//      require(tallyRes(id)(2) == 5 * id)
//    }
//    true
//  }.getOrElse(false)
//}
//
//  /* Test an election with private stake ballots */
//class MultiDelegVotingScenario3(ctx: CryptoContext) extends MultiDelegVotingScenario2(ctx) {
//
//  override def runVoting(sharedPubKey: PubKey): (Seq[MultiDelegPrivateStakeBallot], Seq[MultiDelegExpertBallot]) =
//  {
//    proposalIDs.foldLeft((Seq[MultiDelegPrivateStakeBallot](), Seq[MultiDelegExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
//      val votersBallots =
//        for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
//          val choice = if (voterId % 2 == 1) 0 else 2
//          MultiDelegPrivateStakeBallot.createBallot(pctx, proposalID, DirectMultiDelegVote(choice), sharedPubKey, stake = proposalID, false).get
//        }
//
//      val votersDelegatedBallots = for (_ <- 0 until votersDelegatedNum) yield
//        MultiDelegPrivateStakeBallot.createBallot(pctx, proposalID, DelegatedMultiDelegVote(0), sharedPubKey, stake = proposalID, false).get
//
//      val expertsBallots =
//        for (expertId <- 0 until numberOfExperts) yield
//          MultiDelegExpertBallot.createBallot(pctx, proposalID, expertId, DirectMultiDelegVote(1), sharedPubKey, false).get
//
//      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
//    }
//  }
//}
//
///* Test voting where there are 5 choices to select from */
//class MultiDelegVotingScenario4(ctx: CryptoContext) extends MultiDelegVoting(ctx) {
//
//  val proposalIDs = Set(3, 8)
//  val votersNum = 30
//  val votersDelegatedNum = 20
//  val pctx = new ApprovalContext(ctx, numberOfChoices = 5, numberOfExperts = 5)
//
//  def getContext = pctx
//
//  def runVoting(sharedPubKey: PubKey): (Seq[MultiDelegVoterBallot], Seq[MultiDelegExpertBallot]) =
//  {
//    proposalIDs.foldLeft((Seq[MultiDelegPublicStakeBallot](), Seq[MultiDelegExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
//      val votersBallots =
//        for (voterId <- 0 until votersNum) yield
//          MultiDelegPublicStakeBallot.createBallot(pctx, proposalID, DirectMultiDelegVote(voterId % 5), sharedPubKey, stake = proposalID, false).get
//
//      val votersDelegatedBallots =
//        for (voterId <- 0 until votersDelegatedNum) yield
//          MultiDelegPublicStakeBallot.createBallot(pctx, proposalID, DelegatedMultiDelegVote(voterId % 5), sharedPubKey, stake = proposalID, false).get
//
//      val expertsBallots =
//        for (expertId <- 0 until pctx.numberOfExperts) yield
//          MultiDelegExpertBallot.createBallot(pctx, proposalID, expertId, DirectMultiDelegVote(1), sharedPubKey, false).get
//
//      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
//    }
//  }
//
//  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = Try {
//    require(tallyRes.size == 2)
//    proposalIDs.foreach { id =>
//      require(tallyRes(id).size == 5)
//      require(tallyRes(id)(0) == 6 * id)
//      require(tallyRes(id)(1) == 26 * id)
//      require(tallyRes(id)(3) == 6 * id)
//      require(tallyRes(id)(4) == 6 * id)
//    }
//    true
//  }.getOrElse(false)
//}
