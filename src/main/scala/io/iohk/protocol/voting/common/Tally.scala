package io.iohk.protocol.voting.common

import io.iohk.core.crypto.encryption.{KeyPair, PubKey}
import io.iohk.protocol.keygen.datastructures.round1.R1Data

import scala.util.Try

trait Tally {

  type R1DATA
  type R2DATA
  type R3DATA
  type R4DATA
  type SUMMATOR
  type EXPERTBALLOT
  type RESULT
  type M >: this.type <: Tally

  def generateR1Data(s: SUMMATOR, committeeMemberKey: KeyPair): Try[R1DATA]
  def verifyRound1Data(s: SUMMATOR, committePubKey: PubKey, r1Data: R1DATA): Boolean
  def executeRound1(s: SUMMATOR, r1DataAll: Seq[R1DATA]): Try[M]

  def generateR2Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[R2DATA]
  def verifyRound2Data(committePubKey: PubKey, r2Data: R2DATA, dkgR1DataAll: Seq[R1Data]): Try[Unit]   // TODO: change return type to Boolean
  def executeRound2(r2DataAll: Seq[R2DATA], expertBallots: Seq[EXPERTBALLOT]): Try[M]

  def generateR3Data(committeeMemberKey: KeyPair): Try[R3DATA]
  def verifyRound3Data(committePubKey: PubKey, r3Data: R3DATA): Try[Unit]   // TODO: change return type to Boolean
  def executeRound3(r3DataAll: Seq[R3DATA]): Try[M]

  def generateR4Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[R4DATA]
  def verifyRound4Data(committePubKey: PubKey, r4Data: R4DATA, dkgR1DataAll: Seq[R1Data]): Try[Unit]   // TODO: change return type to Boolean
  def executeRound4(r4DataAll: Seq[R4DATA]): Try[M]

  def getResult: Try[RESULT]
}
