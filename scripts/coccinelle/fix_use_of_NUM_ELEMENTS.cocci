// Copyright (C) 2019 Network RADIUS SAS.  Licenced under GPLv2.
// Development of this scripts was sponsored by Network RADIUS SAS.
// Author: Jorge Pereira (jpereira@freeradius.org)
// Confidence: High
// Comments: Fix use of NUM_ELEMENTS instead of random sizeof(T)/sizeof(E)
// Options: --no-includes
// Example: 
// 
// - printf("Len of test is %d", sizeof(test)/sizeof(*test)));
// + printf("Len of test is %d", NUM_ELEMENTS(test));
// 

@@
type E;
E[] T;
@@
(
-sizeof(T)/sizeof(E)
+NUM_ELEMENTS(T)
|
-sizeof(T)/sizeof(*T)
+NUM_ELEMENTS(T)
|
-sizeof(T)/sizeof(T[...])
+NUM_ELEMENTS(T)
)
