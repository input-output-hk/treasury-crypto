package io.iohk.protocol.keygen_2_0.rnce_encryption.batched

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.encoding.BaseCodec
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight

case class RnceParams(crs: RnceCrsLight)
                     (implicit group: DiscreteLogGroup){
  val chunksMaxNum: Int = RnceParams.maxChunks()
}

object RnceParams {
  def maxChunks()(implicit group: DiscreteLogGroup): Int = {
    // number of chunks that can be produced by BaseCodec on a message of maximal size
    val maxMessage = group.groupOrder - 1
    BaseCodec.encode(maxMessage).seq.length
  }
}
