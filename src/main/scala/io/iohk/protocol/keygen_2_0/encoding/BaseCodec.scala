package io.iohk.protocol.keygen_2_0.encoding

case class BaseEncoding(base: BigInt, seq: Seq[BigInt])

object BaseCodec {

  val defaultBase: BigInt = BigInt(Math.pow(2, 8).toInt)

  def encode(value: BigInt, base: BigInt = defaultBase): BaseEncoding = {
    def encodeInternal(value: BigInt): Seq[BigInt] = {
      if(value < base){
        Seq(value)
      } else {
        val residue = value.mod(base)
        Seq(residue) ++ encodeInternal((value - residue) / base)
      }
    }
    BaseEncoding(base, encodeInternal(value))
  }

  def decode(encoding: BaseEncoding): BigInt = {
    def decodeInternal(seq: Seq[BigInt]): BigInt = {
      seq.headOption match {
        case Some(head) => encoding.base.pow(seq.size - 1) * head + decodeInternal(seq.tail)
        case _ => 0
      }
    }
    decodeInternal(encoding.seq.reverse)
  }

  def decode(seq: Seq[BigInt]): BigInt = {
    decode(BaseEncoding(defaultBase, seq))
  }
}
