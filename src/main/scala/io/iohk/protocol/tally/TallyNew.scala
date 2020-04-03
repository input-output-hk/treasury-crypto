package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.protocol.Identifier
import io.iohk.protocol.keygen.SharedPublicKey
import io.iohk.protocol.keygen.datastructures.round1.R1Data

import scala.util.Try

object TallyPhases extends Enumeration {
  val Init, TallyR1, TallyR2, TallyR3, TallyR4 = Value
}

class TallyNew(cmIdentifier: Identifier[Int], disqualifiedCommitteeMembers: Map[PubKey, PrivKey]) {

  private var currentRound = TallyPhases.Init
  def getCurrentPhase = currentRound

  def recoverState(phase: TallyPhases.Value, storage: RoundsDataStorage)

  def generateR1Data(summator: BallotsSummator, committePrivateKey: PrivKey): Try[TallyR1Data]
  def verifyRound1Data(summator: BallotsSummator, committePubKey: PubKey, r1Data: TallyR1Data): Boolean
  def executeRound1(summator: BallotsSummator, r1DataAll: Seq[TallyR1Data]): Try[]

  def generateR2Data(committePrivateKey: PrivKey, dkgR1Data: Seq[R1Data]): Try[TallyR2Data]
  def verifyRound2Data(committePubKey: PubKey, r2Data: TallyR2Data): Boolean
  def executeRound2(summator: BallotsSummator, r2DataAll: Seq[TallyR2Data]): Try[Delegations]

  def generateR3Data(summator: BallotsSummator, committePrivateKey: PrivKey): Try[TallyR3Data]
  def verifyRound1Data(summator: BallotsSummator, committePubKey: PubKey, r3Data: TallyR1Data): Boolean
  def executeRound1(summator: BallotsSummator, r3DataAll: Seq[TallyR1Data]): Try[TallyR1Data]

  def generateR1Data(summator: BallotsSummator, committePrivateKey: PrivKey): Try[TallyR1Data]
  def verifyRound1Data(summator: BallotsSummator, committePubKey: PubKey, r1Data: TallyR1Data): Boolean
  def executeRound1(summator: BallotsSummator, r1DataAll: Seq[TallyR1Data]): Try[TallyR1Data]
}