package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.voting.{ExpertBallot, PrivateStakeBallot, PublicStakeBallot, VoterBallot}
import io.iohk.protocol.{CryptoContext, ProtocolContext}

import scala.util.Try

trait Elections {
  def run(sharedPubKey: PubKey): (Seq[VoterBallot], Seq[ExpertBallot])
  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean
  def getContext: ProtocolContext
}

class ElectionsScenario1(ctx: CryptoContext) extends Elections {
  private val proposalID = 1
  private val votersNum = 2
  private val numberOfExperts = 2
  val pctx = new ProtocolContext(ctx, 3, numberOfExperts)

  def getContext = pctx

  def run(sharedPubKey: PubKey): (Seq[PublicStakeBallot], Seq[ExpertBallot]) = {
    val votersBallots =
      for (_ <- 0 until votersNum) yield
        PublicStakeBallot.createBallot(pctx, proposalID, 1, sharedPubKey, 3, false).get

    val expertsBallots =
      for (expertId <- 0 until numberOfExperts) yield
        ExpertBallot.createBallot(pctx, proposalID, expertId, 0, sharedPubKey, false).get

    votersBallots -> expertsBallots
  }

  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = {
    if (tallyRes.size == 1) {
      tallyRes(proposalID)(0) == 6 &&
      tallyRes(proposalID)(1) == 0 &&
      tallyRes(proposalID)(2) == 0
    } else false
  }
}

class ElectionsScenario2(ctx: CryptoContext) extends Elections
{
  val proposalIDs = Set(4, 11)
  val votersNum = 10
  val votersDelegatedNum = 20
  val numberOfExperts = 5
  val pctx = new ProtocolContext(ctx, 3, numberOfExperts)

  def getContext = pctx

  def run(sharedPubKey: PubKey): (Seq[VoterBallot], Seq[ExpertBallot]) =
  {
    proposalIDs.foldLeft((Seq[PublicStakeBallot](), Seq[ExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
      val votersBallots =
        for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
          val vote = if (voterId % 2 == 1) pctx.numberOfExperts else pctx.numberOfExperts + 2
          PublicStakeBallot.createBallot(pctx, proposalID, vote, sharedPubKey, stake = proposalID, false).get
        }

      val votersDelegatedBallots =
        for (_ <- 0 until votersDelegatedNum) yield
          PublicStakeBallot.createBallot(pctx, proposalID, 0, sharedPubKey, stake = proposalID, false).get

      val expertsBallots =
        for (expertId <- 0 until numberOfExperts) yield
          ExpertBallot.createBallot(pctx, proposalID, expertId, 1, sharedPubKey,false).get

      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
    }
  }

  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = Try {
    require(tallyRes.size == 2)
    proposalIDs.foreach { id =>
      require(tallyRes(id)(0) == 5 * id)
      require(tallyRes(id)(1) == 20 * id)
      require(tallyRes(id)(2) == 5 * id)
    }
    true
  }.getOrElse(false)
}

/* Test an election with private stake ballots */
class ElectionsScenario3(ctx: CryptoContext) extends ElectionsScenario2(ctx)
{
  override def run(sharedPubKey: PubKey): (Seq[PrivateStakeBallot], Seq[ExpertBallot]) =
  {
    proposalIDs.foldLeft((Seq[PrivateStakeBallot](), Seq[ExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
      val votersBallots =
        for (voterId <- numberOfExperts until (numberOfExperts + votersNum)) yield {
          val vote = if (voterId % 2 == 1) pctx.numberOfExperts else pctx.numberOfExperts + 2
          PrivateStakeBallot.createBallot(pctx, proposalID, vote, sharedPubKey, stake = proposalID, false).get
        }

      val votersDelegatedBallots = for (_ <- 0 until votersDelegatedNum) yield
          PrivateStakeBallot.createBallot(pctx, proposalID, 0, sharedPubKey, stake = proposalID, false).get

      val expertsBallots =
        for (expertId <- 0 until numberOfExperts) yield
          ExpertBallot.createBallot(pctx, proposalID, expertId, 1, sharedPubKey, false).get

      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
    }
  }
}

/* Test voting where there are 5 choices to select from */
class ElectionsScenario4(ctx: CryptoContext) extends Elections
{
  val proposalIDs = Set(3, 8)
  val votersNum = 30
  val votersDelegatedNum = 20
  val pctx = new ProtocolContext(ctx, numberOfChoices = 5, numberOfExperts = 5)

  def getContext = pctx

  def run(sharedPubKey: PubKey): (Seq[VoterBallot], Seq[ExpertBallot]) =
  {
    proposalIDs.foldLeft((Seq[PublicStakeBallot](), Seq[ExpertBallot]())) { case ((vAcc, eAcc), proposalID) =>
      val votersBallots =
        for (voterId <- 0 until votersNum) yield {
          val vote = pctx.numberOfExperts + voterId % 5
          PublicStakeBallot.createBallot(pctx, proposalID, vote, sharedPubKey, stake = proposalID, false).get
        }

      val votersDelegatedBallots =
        for (voterId <- 0 until votersDelegatedNum) yield
          PublicStakeBallot.createBallot(pctx, proposalID, voterId % 5, sharedPubKey, stake = proposalID, false).get

      val expertsBallots =
        for (expertId <- 0 until pctx.numberOfExperts) yield
          ExpertBallot.createBallot(pctx, proposalID, expertId, 1, sharedPubKey, false).get

      (vAcc ++ votersBallots ++ votersDelegatedBallots) -> (eAcc ++ expertsBallots)
    }
  }

  def verify(tallyRes: Map[Int, Vector[BigInt]]): Boolean = Try {
    require(tallyRes.size == 2)
    proposalIDs.foreach { id =>
      require(tallyRes(id).size == 5)
      require(tallyRes(id)(0) == 6 * id)
      require(tallyRes(id)(1) == 26 * id)
      require(tallyRes(id)(3) == 6 * id)
      require(tallyRes(id)(4) == 6 * id)
    }
    true
  }.getOrElse(false)
}