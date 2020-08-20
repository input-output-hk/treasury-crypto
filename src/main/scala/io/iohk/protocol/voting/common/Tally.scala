package io.iohk.protocol.voting.common

import io.iohk.core.crypto.encryption.{KeyPair, PubKey}
import io.iohk.protocol.keygen.datastructures.round1.R1Data

import scala.util.Try

/**
  * Tally trait is a common interface for the 4-round tally protocol.
  *
  * First round is a delegations decryption: during the first round committee members submit decryption shares needed
  * to decrypt the amount of delegated stake to each expert.
  *
  * Second round is a recovery round for delegations decryption: committee members submit recovery shares needed to restore
  * secret keys of those members who failed to submit valid decryption shares in the first round, so that given restored keys
  * everyone can reconstruct missing decryption shares.
  *
  * Third round is a voting result decryption: committee members submit decryption shares needed to decrypt the voting result
  * for each proposal.
  *
  * Fourth round is a recovery round for result decryption: committee members submit recovery shares needed to restore
  * secret keys of those members who failed to submit valid decryption shares in the third round, so that given the restored
  * keys everyone can reconstruct missing decryption shares.
  *
  * See details of the protocol in the spec: treasury-crypto/docs/voting_protocol_spec/Treasury_voting_protocol_spec.pdf
  *
  * The Tally class is supposed to be used both by committee members, who participate in the protocol, and regular observers,
  * who are able to verify each message and calculate the tally result for each proposal.
  *
  * The interface is the following, each round is represented by 3 functions (X is a round number):
  *   - generateRXData    - is used by a committee member to generate a round-specific data;
  *   - verifyRXData      - is used by everyone who follows the tally protocol to verify a round-specific data produced
  *                         by a committee member (e.g., in a blockchain setting, if a round-specific data is submitted as
  *                         a transaction, verifyRXData will be used by every node to verify such transaction);
  *   - executeRoundX     - is used by everyone to update the state according to the provided set of round-specific data
  *                         from committee members. Note that it is responsibility of the caller to verify the data provided
  *                         to the "executeRoundX";
  * Note that Tally is a stateful class. Each successful call to the "executeRoundX" function updates internal variables. On the
  * other hand, calls to "generateRXData" and "verifyRXData" don't produce any side-effects.
  * Also note that "executeRoundX" should be called sequentially one after another, otherwise they will return error.
  */
trait Tally {

  type R1DATA <: Issuer
  type R2DATA <: Issuer
  type R3DATA <: Issuer
  type R4DATA <: Issuer
  type SUMMATOR
  type VOTERBALLOT
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
