package io.iohk.protocol.voting.preferential.tally

import io.iohk.protocol.keygen.datastructures.round5_1.ViolatorsSharesData

package object datastructures {
  type PrefTallyR2Data = ViolatorsSharesData
  type PrefTallyR3Data =  PrefTallyR1Data
  type PrefTallyR4Data =  PrefTallyR2Data
}
