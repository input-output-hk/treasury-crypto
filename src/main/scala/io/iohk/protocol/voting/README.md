Voting schemes
====================================================================================================================================================================================
There three types of voting schemes implemented:
1. Approval voting with multiple delegation
2. Approval voting with unified delegation
3. Preferential voting

They are similar to each other in many aspects, but have differences in how a vote is represented and tallied.

Note that different voting schemes can be combined to have multi-stage voting system. For instance, [TwoStageVoting.scala](https://github.com/input-output-hk/treasury-crypto/blob/dev/src/test/scala/io/iohk/protocol/integration/TwoStageVoting.scala) implements a two-stage voting system, where on the first stage an initial set of proposals is filtered by preferential voting and then, on the second stage, each selected proposal is voted with approval voting scheme.

Approval voting with multiple delegation
-------------------
In this scheme each registered proposal is voted separately by a voter. 
For each proposal there are a set of options to vote (e.g, Yes/No/Abstain).
At the end votes of all voters are summed up so that for each proposal there are numbers of votes for each option.

A voter can delegate for each proposal separately. E.g., he can vote directly for some proposals and delegate his voting rights for the rest of proposals to different experts.

A ballot in this scheme represents a vote for one proposal. So if there are many proposals, a voter should issue several ballots. 

Approval voting with unified delegation
-------------------
This scheme is similar to the previous one except that votes for all proposals are inserted in the same ballot.
Moreover, a voter cannot delegate separately for different proposals. He either delegate the voting rights for all proposals to one expert or votes directly for all proposals.

Preferential voting
-------------------
In this scheme a vote is represented as a ranked list of proposal IDs. A voter is asked to chose N proposals among all registered and rank them according to preferences. N is a system parameter.

For instance, if N=5, each voter submits a list of 5 proposal IDs according to preferences. The first proposal in the list gets 5 points, the second - 4 points and so on. At the end scores of all voters for all proposals are summed and final score for each proposal is calculated.

A voter can delegate his voting right to one expert.