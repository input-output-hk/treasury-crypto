package treasury.crypto.keygen

import treasury.crypto.core.{Cryptosystem, KeyPair, Point, PrivKey, PubKey}

class CommitteeMember(val cs: Cryptosystem, val h: Point, val transportKeyPair: KeyPair, val committeeMembersPubKeys: Seq[PubKey] ) {

  private val dkg = new DistrKeyGen(cs, h, transportKeyPair, committeeMembersPubKeys)
  val secretKey = cs.getRand
  val ownId: Integer = dkg.ownID

  def setKeyR1(): R1Data = {
    dkg.doRound1(secretKey.toByteArray)
  }

  def setKeyR2(r1Data: Seq[R1Data]): R2Data = {
    dkg.doRound2(r1Data)
  }

  def setKeyR3(r2Data: Seq[R2Data]): R3Data = {
    dkg.doRound3(r2Data)
  }

  def setKeyR4(r3Data: Seq[R3Data]): R4Data = {
    dkg.doRound4(r3Data)
  }

  def setKeyR5_1(r4Data: Seq[R4Data]): R5_1Data = {
    dkg.doRound5_1(r4Data)
  }

  def setKeyR5_2(r5_1Data: Seq[R5_1Data]): R5_2Data = {
    dkg.doRound5_2(r5_1Data)
  }
}
