package treasury.crypto.core.primitives.hash.bouncycastle

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import treasury.crypto.core.primitives.hash.SHA3_256_Hash

object SHA3_256_HashBc extends SHA3_256_Hash {

  override def algorithmName: String = "SHA-3 256 BouncyCastle"

  override val digestSize: Int = 32

  val digestSizeInBits: Int = 256

  override def hash(input: Array[Byte]): Array[Byte] = {
    val md = new DigestSHA3(digestSizeInBits)
    md.update(input)
    md.digest
  }
}
