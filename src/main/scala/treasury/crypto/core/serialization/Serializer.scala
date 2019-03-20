package treasury.crypto.core.serialization

import scala.util.Try

trait Serializer[M,D] {

  def toBytes(obj: M): Array[Byte]

  /**
    * Deserializes an object from bytes. Note that in some cases a deserialized object needs a special decoder.
    * For instance, a serialized elliptic curve point may need a EC group instance to be decerialized.
    * Such additional context can be passed through the decoder parameter.
    *
    * @param bytes serialized object
    * @param decoder special decoder if needed
    * @return reconstructed object in Try
    */
  def parseBytes(bytes: Array[Byte], decoder: Option[D] = None): Try[M]
}
