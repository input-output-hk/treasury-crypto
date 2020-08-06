package io.iohk.protocol.voting.approval.multi_delegation.tally

import io.iohk.protocol.keygen.datastructures.round5_1.ViolatorsSharesData

package object datastructures {

  type TallyR2Data = ViolatorsSharesData
  type TallyR3Data = MultiDelegTallyR1Data
  type TallyR4Data = TallyR2Data
}
