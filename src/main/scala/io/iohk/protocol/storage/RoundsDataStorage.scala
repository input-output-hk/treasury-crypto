package io.iohk.protocol.storage

import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round2.R2Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.R4Data
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2Data
import io.iohk.protocol.voting.approval.multi_delegation.tally.datastructures.{MultiDelegTallyR1Data, MultiDelegTallyR2Data, MultiDelegTallyR3Data, MultiDelegTallyR4Data}
import io.iohk.protocol.voting.approval.multi_delegation.{MultiDelegExpertBallot, MultiDelegVoterBallot}

import scala.util.Try

/**
  * RoundsDataStorage is supposed to be an interface for accessing different data generated during the
  * protocol execution. The main idea is to abstract the storage layer, so that there is freedom to chose what
  * is more suitable for particular application (e.g., if there are not many data it can be put to RAM or else to HDD,
  * or if there is a blockchain it can extract needed data from blocks)
  *
  * TODO: currently it is barely used (only Tally uses RoundsDataStorage for recovery). But probably it make sense to
  * integrate it also to other parts of the protocol (e.g., DKG).
  * TODO: currently each round has its own setter and getter, which I guess can be improved. Think
  * about creating a basic class for all round data structures
  */
trait RoundsDataStorage {

  /*
   * DKG data. DKG protocol has 5 rounds (note that the fifth round is divided into two sub-rounds). At each round,
   * each committee member generates and submits a package with corresponding data.
   */
  def getDKGr1: Seq[R1Data]
  def updateDKGr1(data: Seq[R1Data]): Try[Unit]

  def getDKGr2: Seq[R2Data]
  def updateDKGr2(data: Seq[R2Data]): Try[Unit]

  def getDKGr3: Seq[R3Data]
  def updateDKGr3(data: Seq[R3Data]): Try[Unit]

  def getDKGr4: Seq[R4Data]
  def updateDKGr4(data: Seq[R4Data]): Try[Unit]

  def getDKGr5_1: Seq[R5_1Data]
  def updateDKGr5_1(data: Seq[R5_1Data]): Try[Unit]

  def getDKGr5_2: Seq[R5_2Data]
  def updateDKGr5_2(data: Seq[R5_2Data]): Try[Unit]

  /*
   * Ballots data. During the voting stage voters and experts submit their ballots. For each proposal there should be
   * a separate ballot that contains an encrypted unit vector with user's choice. Though, it is assumed that voters will post
   * a single transaction with the ballots for all proposals at once.
   *
   * We differentiate between regular voter and expert, because their ballots are handled differently.
   */

  def getVoterBallots: Seq[MultiDelegVoterBallot]
  def updateVotersBallots(data: Seq[MultiDelegVoterBallot]): Try[Unit]

  def getExpertBallots: Seq[MultiDelegExpertBallot]
  def updateExpertBallots(data: Seq[MultiDelegExpertBallot]): Try[Unit]

  /*
   * Tally data. Tally protocol has 4 rounds. At each round, each committe member generates and submits a package with
   * corresponding data.
   */
  def getTallyR1: Seq[MultiDelegTallyR1Data]
  def updateTallyR1(data: Seq[MultiDelegTallyR1Data]): Try[Unit]

  def getTallyR2: Seq[MultiDelegTallyR2Data]
  def updateTallyR2(data: Seq[MultiDelegTallyR2Data]): Try[Unit]

  def getTallyR3: Seq[MultiDelegTallyR3Data]
  def updateTallyR3(data: Seq[MultiDelegTallyR3Data]): Try[Unit]

  def getTallyR4: Seq[MultiDelegTallyR4Data]
  def updateTallyR4(data: Seq[MultiDelegTallyR4Data]): Try[Unit]
}
