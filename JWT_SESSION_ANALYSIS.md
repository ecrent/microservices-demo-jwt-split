
Header	Total Uses	Literal	Indexed	Indexing Rate
x-jwt-static	6,413	1,201	5,212	81.3%
x-jwt-session	6,413	5,091	1,322	20.6%
x-jwt-dynamic-bin	6,413	5,107	1,306	20.4%
x-jwt-sig-bin	6,413	5,107	1,306	20.4%
TOTAL	25,652	16,506	9,146	35.7%


For user eae02015's x-jwt-session:

Frame 13 (t=0.14s): Literal - first request, adds to table
Frame 72 (t=3.0s): Literal - evicted from table, re-added
Frame 86 (t=3.0s): Literal - evicted again
Frame 144 (t=4.1s): Literal - evicted again
Frame 333 (t=6.3s): Indexed - still in table! ✓
Frame 5804 (t=137.5s): Indexed - still in table! ✓
Frame 5863 (t=139.5s): Literal - evicted
Frame 5883 (t=139.6s): Literal - evicted
Frame 6118 (t=143.7s): Literal - evicted