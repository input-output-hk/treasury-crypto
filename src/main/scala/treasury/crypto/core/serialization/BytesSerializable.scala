package treasury.crypto.core.serialization

/**
  * Sometimes decoder is not needed. In this case the DECODER type can be defined as NODECODER
  */
trait NODECODER

trait BytesSerializable extends Serializable {

  type M >: this.type <: BytesSerializable
  type DECODER

  //lazy val bytes: Array[Byte] = serializer.toBytes(this)

  def bytes: Array[Byte] = serializer.toBytes(this)

  def serializer: Serializer[M, DECODER]
}