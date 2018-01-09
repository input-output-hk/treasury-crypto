package treasury.crypto.core.serialization

import treasury.crypto.core.Cryptosystem

import scala.util.Try

trait Serializer[M] {

  def toBytes(obj: M): Array[Byte]

  def parseBytes(bytes: Array[Byte], cs: Cryptosystem): Try[M]
}
