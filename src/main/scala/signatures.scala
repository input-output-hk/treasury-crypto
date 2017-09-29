
package object signatures {

  type PrivKey = Array[Byte]

  type PubKey = Array[Byte]

  type Ciphertext = (Array[Byte], Array[Byte])

  type Message = Int

  type Randomness = Array[Byte]
}
