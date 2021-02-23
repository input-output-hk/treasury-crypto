Voting schemes
====================================================================================================================================================================================
There are three types of voting schemes implemented:
1. Approval voting with multiple delegation
2. Approval voting with unified delegation
3. Preferential voting

Read more details about voting schemes here [README.md](https://github.com/input-output-hk/treasury-crypto/blob/dev/src/main/scala/io/iohk/protocol/voting/README.md)

Approval voting with unified delegation
-------------------

### Raw benchmarks:

    Commitee members:	2
    Commitee violators:	0 (0%)
    Voters: 	5000
    Experts:	0
    Stake per voter (normalized by granularity): 	1066
    Proposals: 	1
    ------------------------
    Voter ballots traffic: 3945 kB
    Expert ballots traffic: 0 kB

    Tally Round 1 (data generation):	0.002146882 s;	Tally Round 1 (execution): 0 ms
    Round 1 traffic: 0 kB
    Tally Round 2 (data generation):	0.00127362 s;	Tally Round 2 (execution): 2 ms
    Round 2 traffic: 0 kB
    Tally Round 3 (data generation):	0.011880303 s;	Tally Round 3 (execution): 3 ms
    Round 3 traffic: 0 kB
    Tally Round 4 (data generation):	6.10907E-4 s;	Tally Round 4 (execution): 102079 ms
    Round 4 traffic: 0 kB
    ----------------------------------
    Overall time (for one committee member for data generation):    0.015911711 sec
    Overall traffic:                            4040436 Bytes (3945 KB)
    -----------------------------------

### Analytical estimations based on raw benchmarks:
    Commitee members:       2
    Voters:                 5000
    Experts:                0
    Stake per voter:        106 600
    Stake granularity:      100
    Overall participating stake: 533 000 000
    Proposals:              150
    ------------------------
    Voter ballots traffic:     577 mB
    Expert ballots traffic:    0 mB
    Committee members traffic: negligible
    ------------------------
    Tally time: 15300 sec (4.25 hours)

Approval voting with multiple delegation
-------------------
If number of experts is zero, benchmarks are exactly the same as for uni delegation approval voting. In case number of experts > 0, the size of ballots will grow linearly to number of experts multiplied by number of proposals. Tally time should be the same. 

Preferential voting
-------------------

### Raw benchmarks:
    Commitee members:	2
    Commitee violators:	0 (0%)
    Voters: 	500
    Experts:	0
    Stake per voter (normalized by granularity): 	10660
    Proposals: 	50
    Ranked proposals:	5
    ------------------------
    Voter ballots traffic: 31195 kB
    Expert ballots traffic: 0 kB
    
    Tally Round 1 (data generation):	0.003141246 s;	Tally Round 1 (execution): 0 ms
    Round 1 traffic: 0 kB
    Tally Round 2 (data generation):	0.001813392 s;	Tally Round 2 (execution): 2 ms
    Round 2 traffic: 0 kB
    Tally Round 3 (data generation):	0.7601703 s;	Tally Round 3 (execution): 5 ms
    Round 3 traffic: 33 kB
    Tally Round 4 (data generation):	9.34549E-4 s;	Tally Round 4 (execution): 519686 ms
    Round 4 traffic: 0 kB
    ----------------------------------
    Overall time (for one committee member):    0.76605946 sec
    Overall traffic:                            31978494 Bytes (31228 KB)
    -----------------------------------