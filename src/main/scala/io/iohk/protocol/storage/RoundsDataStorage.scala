package io.iohk.protocol.storage

import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round2.R2Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.R4Data
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2Data
import io.iohk.protocol.voting.ballots.{ExpertBallot, VoterBallot}

import scala.util.Try

/**
  * Holds data generated and published by committee members during the protocol execution.
  * It is assumed that each piece of round data is submitted as a separate transaction.
  */
//trait RoundsDataStorage {
//
//  /*
//   * DKG data. DKG protocol has 5 rounds (note that the fifth round is divided into two sub-rounds). At each round,
//   * each committee member generates and submits a package with corresponding data.
//   */
//  def getDKGr1: Seq[R1Data]
//  def updateDKGr1(data: Seq[R1Data]): Try[Int]
//
//  def getDKGr2: Seq[R2Data]
//  def updateDKGr2(data: Seq[R2Data]): Try[Int]
//
//  def getDKGr3: Seq[R3Data]
//  def updateDKGr3(data: Seq[R3Data]): Try[Int]
//
//  def getDKGr4: Seq[R4Data]
//  def updateDKGr4(data: Seq[R4Data]): Try[Int]
//
//  def getDKGr5_1: Seq[R5_1Data]
//  def updateDKGr5_1(data: Seq[R5_1Data]): Try[Int]
//
//  def getDKGr5_2: Seq[R5_2Data]
//  def updateDKGr5_2(data: Seq[R5_2Data]): Try[Int]
//
//  /*
//   * Ballots data. During the voting stage voters and experts submit their ballots. For each proposal there should be
//   * a separate ballot that contains an encrypted unit vector with user's choice. Though, it is assumed that voters will post
//   * a single transaction with the ballots for all proposals at once.
//   *
//   * We differentiate between regular voter and expert, because their ballots are handled differently.
//   */
//
////  def getVoterBallots(proposalID: Int): Seq[VoterBallot]
////  def updateVotersBallots(data: Seq[VoterBallot]): Try[Int]
////
////  def getExpertBallots(proposalID): Seq[ExpertBallot]
////  def updateExpertBallots(data: Seq[ExpertBallot]): Try[Int]
//
//  /*
//   * Tally data. Tally protocol has 4 rounds. At each round, each committe member generates and submits a package with
//   * corresponding data.
//   */
//  def getTallyR1: Seq[]
//  def updateTallyR1(data: Seq[]): Try[Int]
//
//  def getTallyR2: Seq[]
//  def updateTallyR2(data: Seq[]): Try[Int]
//
//  def getTallyR3: Seq[]
//  def updateTallyR3(data: Seq[]): Try[Int]
//
//  def getTallyR4: Seq[]
//  def updateTallyR4(data: Seq[]): Try[Int]
//
//  /*
//   *
//   */
//
//  def getRandGenCommit: Seq[]
//  def updateRandGenCommit(data: Seq[]): Try[Int]
//
//  def getRandGenRevealR1: Seq[]
//  def updateRandGenRevealR1(data: Seq[]): Try[Int]
//
//  def getRandGenRevealR2: Seq[]
//  def updateRandGenRevealR2(data: Seq[]): Try[Int]
//}
