package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.protocol.keygen.datastructures.round5_1.ViolatorsSharesData
import io.iohk.protocol.voting.preferential.tally.datastructures.PrefTallyR1Data

package object datastructures {
  type UniDelegTallyR1Data = PrefTallyR1Data      // R1Data is completely the same as PrefTallyR1Data, so use it
  type UniDelegTallyR2Data = ViolatorsSharesData
  type UniDelegTallyR4Data = ViolatorsSharesData
}
