package io.iohk.protocol.voting.approval.multi_delegation.tally

import io.iohk.protocol.keygen.datastructures.round5_1.ViolatorsSharesData

package object datastructures {

  type MultiDelegTallyR2Data = ViolatorsSharesData
  type MultiDelegTallyR3Data = MultiDelegTallyR1Data
  type MultiDelegTallyR4Data = MultiDelegTallyR2Data
}
