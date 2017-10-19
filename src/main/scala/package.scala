
package object common {

  type PrivKey = Array[Byte]
  type PubKey = Array[Byte]
  type Ciphertext = (Array[Byte], Array[Byte])
  type Message = Int
  type Randomness = Array[Byte]
  type Element = Array[Byte]

  case class TallyResult(val yes: Int, val no: Int, val abstain: Int)

  object VoteCases extends Enumeration {
    val Yes, No, Abstain = Value
  }
}
