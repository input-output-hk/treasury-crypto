package treasury.crypto.keygen

import java.math.BigInteger
import java.util.Random

import org.bouncycastle.jce.spec.ECParameterSpec

class CommitteeMember(val ecSpec: ECParameterSpec, val g: Array[Byte], val h: Array[Byte], val ownID: Integer, val committeeMembersAttrs: Seq[CommitteeMemberAttr] ) {

  val dkg = new DistrKeyGen(ecSpec, ecSpec.getCurve.decodePoint(g), ecSpec.getCurve.decodePoint(h), ownID, committeeMembersAttrs)
  val secretKey = new BigInteger(ecSpec.getN.bitLength(), new Random).mod(ecSpec.getN)

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

  def setKeyR5_2(r5_1Data: Seq[R5_1Data]): SharedPublicKey = {
    dkg.doRound5_2(r5_1Data)
  }
}
