// Package versions lists client versions that TeamSpeak servers accept.
//
// A [ClientVersion] is the platform, version string and signature that an
// official TeamSpeak client sent in its clientinit. Each variable in this
// package is one such version, with the signature it was sent with. Pass one to
// client.WithVersion to connect as that version:
//
//	client.New(id, addr, "Bot", client.WithVersion(versions.Windows_3_6_2_1695203293))
//
// Signatures cannot be made, only reused, so a version that is not listed here
// cannot be sent. A server refuses a build below its configured minimum.
//
// The variables are values for reading: callers must not modify them. In a
// platform name that would start in lower case, the first letter is
// capitalised so the name is exported: macOS is MacOS and iOS is IOS.
package versions

// ClientVersion identifies a client build to a server.
type ClientVersion struct {
	// Platform is the client_platform the server is told, such as "Windows".
	Platform string
	// Version is the client_version the server is told, with its build number.
	Version string
	// Sign is the base64 signature over Platform followed by Version.
	Sign string
}

// Windows_3_0_11_1374563791 is Windows 3.0.11, build 1374563791.
var Windows_3_0_11_1374563791 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.11 [Build: 1374563791]",
	Sign:     "hQCwiLP5f4GIcDG5KQ1T+CNFGqRxyw5MXCHE8KjWRIgkjCuGSryK4vpPy70EURH3blQ8TKrax8BEorHlpnpdAQ==",
}

// Windows_3_0_11_1374830986 is Windows 3.0.11, build 1374830986.
var Windows_3_0_11_1374830986 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.11 [Build: 1374830986]",
	Sign:     "PJvjEuApy2McckLGGnAgw8kB2FE+yb4J/TuUdaLj+x5JVghSBR5tKJDQklLurJrshKynWzYYtokrtgBxTAz5CA==",
}

// Windows_3_0_11_1375083581 is Windows 3.0.11, build 1375083581.
var Windows_3_0_11_1375083581 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.11 [Build: 1375083581]",
	Sign:     "54wPDkfv0kT56UE0lv/LFkFJObH+Q4Irmo4Brfz1EcvjVhj8hJ+RCHcVTZsdKU2XvVvh+VLJpURulEHsAOsyBw==",
}

// Windows_3_0_11_1_1375367141 is Windows 3.0.11.1, build 1375367141.
var Windows_3_0_11_1_1375367141 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.11.1 [Build: 1375367141]",
	Sign:     "2xNEoMd2TBeOj6PRSEftjE0fTSjq9dnqt8ttFVYdS3Kp9NHX/jBNycD3XCnNtsmHtHgQkczq1x2qQb1KFfg5Cw==",
}

// Windows_3_0_11_1_1375773286 is Windows 3.0.11.1, build 1375773286.
var Windows_3_0_11_1_1375773286 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.11.1 [Build: 1375773286]",
	Sign:     "Qfvcn4uQmKETDsD4LbtdbZR8rDetJ26Z/bVbu5SZJjMjGlYEMSbJnR4PtOBshdMSEwEsAJf1G+5tjx+onm2fDA==",
}

// Linux_3_0_11_1_1375773286 is Linux 3.0.11.1, build 1375773286.
var Linux_3_0_11_1_1375773286 = ClientVersion{
	Platform: "Linux",
	Version:  "3.0.11.1 [Build: 1375773286]",
	Sign:     "JMTTCSHw+ibyhqCDCWRgby/oJ5uAYHk0/QOwqqI5rNHCKTkb+ce6N+4J38WXAnRmtcEaMb0s30s3ipQBokrqDw==",
}

// OSX_3_0_11_1_1375773286 is OS X 3.0.11.1, build 1375773286.
var OSX_3_0_11_1_1375773286 = ClientVersion{
	Platform: "OS X",
	Version:  "3.0.11.1 [Build: 1375773286]",
	Sign:     "BngQ1112epNzhND5v7uDdbClbP9dSWczXKxvi1iRQo+xWt7WLYKJu/05MrW/CtPVtKwlT4PnbfI0Trvw+HvUCA==",
}

// Windows_3_0_12_1378199876 is Windows 3.0.12, build 1378199876.
var Windows_3_0_12_1378199876 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.12 [Build: 1378199876]",
	Sign:     "1uVn+Px0c733pYcYmid+3MwrJaq2KMIzvqIktMkICNhOYPViYfwUqTbFHMMx/CzLNKEevP57HyQ1TFdGdPU7BQ==",
}

// Windows_3_0_12_1378301061 is Windows 3.0.12, build 1378301061.
var Windows_3_0_12_1378301061 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.12 [Build: 1378301061]",
	Sign:     "bbShDADD1HUCnPI7F4EG92k0L5qU3M+vsMOZu94xdMfw6Ru1mo6UZ/ctNnrDPHsFZjcSUPOV2myjurknhaUUCg==",
}

// Windows_3_0_12_1378461722 is Windows 3.0.12, build 1378461722.
var Windows_3_0_12_1378461722 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.12 [Build: 1378461722]",
	Sign:     "3z7xnPRdMYJ3S+w6Jx7XyzpiXI2Cu+zSMG4Gr+F9cgKAWvdFp6dPvysT9bBtrkDWWL+hnZluCx/+1fmEcjXrAg==",
}

// Windows_3_0_12_1378715177 is Windows 3.0.12, build 1378715177.
var Windows_3_0_12_1378715177 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.12 [Build: 1378715177]",
	Sign:     "x6wFA5xqjenf6kbAh36IC4CkrbT8/uSBpgjM9juSt9oxGCXLqHOC2oaYlB1zZSJZjT4sOrnp0M+uOdVjYCzLCg==",
}

// Windows_3_0_13_1380008864 is Windows 3.0.13, build 1380008864.
var Windows_3_0_13_1380008864 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.13 [Build: 1380008864]",
	Sign:     "E/MlNft7LXOD5AdgVE8ekxWyrBXDXmfM+I2GDhUiOxlyIzXf0LLq7xtiq79yNqp1CLT3SYKFtIZhaT+YWUqKCw==",
}

// Windows_3_0_13_1380283653 is Windows 3.0.13, build 1380283653.
var Windows_3_0_13_1380283653 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.13 [Build: 1380283653]",
	Sign:     "7dA+6EbVyMevol4gE3/Cu1WonRjqu1C6pTWF+txApbaiTgKtZ/ky+NVxluPkSDnCxXN1pOR4uGdF6B7LUqQgDQ==",
}

// Android_3_0_13_1380616389 is Android 3.0.13, build 1380616389.
var Android_3_0_13_1380616389 = ClientVersion{
	Platform: "Android",
	Version:  "3.0.13 [Build: 1380616389]",
	Sign:     "04JRo/B0zh54n18a61qWr3qFUrEVQeEiy7dyIEVhCLMwY8QJwk7kwG7GQKSxnr0rmRfTzD7iDXMUWlcwgkc/Cg==",
}

// Windows_3_0_13_1_1382530211 is Windows 3.0.13.1, build 1382530211.
var Windows_3_0_13_1_1382530211 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.13.1 [Build: 1382530211]",
	Sign:     "bCIfLPUgTM6C0kNkesvhcxaDPvV9h6qLbYVy9cQVSP5lzaYebZaeDzAOOHsdjKcRTa6LU1oHEdz9D/d+2gxJCw==",
}

// OSX_3_0_13_1_1382530211 is OS X 3.0.13.1, build 1382530211.
var OSX_3_0_13_1_1382530211 = ClientVersion{
	Platform: "OS X",
	Version:  "3.0.13.1 [Build: 1382530211]",
	Sign:     "0KNdNcf2zmYUV7JzfKlXdM0Y6/dv9LOlETE8h2mTxq0YitdbZSObUdAJvrdiKX0LH2QP4h3QF2JeXyzjRSQTCw==",
}

// Windows_3_0_14_1387444094 is Windows 3.0.14, build 1387444094.
var Windows_3_0_14_1387444094 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.14 [Build: 1387444094]",
	Sign:     "3BFPkbf8KQ3udBXLoMpm41txWJ2M+vsKzXYVaBMCr4xSiPBcdnol8lUgrBLV3dNIHjGZlZXqmqtz+/qmsnu0Bw==",
}

// Windows_3_0_14_1392643117 is Windows 3.0.14, build 1392643117.
var Windows_3_0_14_1392643117 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.14 [Build: 1392643117]",
	Sign:     "/k5bfFDSb0KBHNO5BBloS2vvVXu2S9iuxRa8L9prP+zbfR/EoGuzz1Vlpm/pxxeDQpcJ7oLog9wsdgBAF0nVAg==",
}

// Windows_3_0_14_1393597517 is Windows 3.0.14, build 1393597517.
var Windows_3_0_14_1393597517 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.14 [Build: 1393597517]",
	Sign:     "vKRbu9Nf8d54bAEJAywHU9qIhpR89dvcmq0ff+Ak+umKqLKzMl02YwP9qx+oSgj5UQOpt9nMST/8puhHmD9QBQ==",
}

// Windows_3_0_14_1394114560 is Windows 3.0.14, build 1394114560.
var Windows_3_0_14_1394114560 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.14 [Build: 1394114560]",
	Sign:     "mxBQYmj5bfirNWiVvbsFT8ybN2oov3CQ0fQmBpHWgBBJk9EM8NKmqMCpfpqVLFcubkCK7gs1hbYRXQ5DhuixBQ==",
}

// Windows_3_0_14_1394624943 is Windows 3.0.14, build 1394624943.
var Windows_3_0_14_1394624943 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.14 [Build: 1394624943]",
	Sign:     "F0WIO9sBVzG893AtX2Jfd98cH6yZPAnfMBNvBlQbAIfvfyiq+cbjZ31AUngEjq7UPIYdnYSsdRX9hczwdBrKAQ==",
}

// Windows_3_0_15_1401808190 is Windows 3.0.15, build 1401808190.
var Windows_3_0_15_1401808190 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.15 [Build: 1401808190]",
	Sign:     "Bo28W8+xHTRqVAiayKwRSmp1iojqY8NhhuhjSbvbovx9Mby8YNTWdY7/HHCfOt+nEYLhcGnxcssR0aJhShItAw==",
}

// Windows_3_0_15_1402646489 is Windows 3.0.15, build 1402646489.
var Windows_3_0_15_1402646489 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.15 [Build: 1402646489]",
	Sign:     "Jv5wg8X7HZv2NwbAX8b9L5gyDFN3mPI1veCRV/IbxwvRVzS0PL1vvHqDJYfyjIsrtM0VPLBhnuF4PswmEdueBA==",
}

// Windows_3_0_15_1403250090 is Windows 3.0.15, build 1403250090.
var Windows_3_0_15_1403250090 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.15 [Build: 1403250090]",
	Sign:     "FKKAHPwV1swKwH6mqHqdcGuYm8o5mZw4WreBxJrQjOprC3NXXcJviPe0p7EZPI810HOWMfmQRUgFpggoRL8kAQ==",
}

// Windows_3_0_15_1_1405341092 is Windows 3.0.15.1, build 1405341092.
var Windows_3_0_15_1_1405341092 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.15.1 [Build: 1405341092]",
	Sign:     "b+hr0KQWOVW2WEn49BmNb08R9zimsJcThm2gEeF7EAgRUeUDYzeplh5HrHmda0ftbbnrzWV33U/GOo2LAs/rAg==",
}

// Windows_3_0_16_1406898538 is Windows 3.0.16, build 1406898538.
var Windows_3_0_16_1406898538 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.16 [Build: 1406898538]",
	Sign:     "UoK5KLpRJfF9KnF9EURK8CbdI4WgjigfvVVgSUc9lokIvCpFTYwGuKfgL4oW8I1ldnzHTbs1Q0gtGcrzI0KwBQ==",
}

// Windows_3_0_16_1407159763 is Windows 3.0.16, build 1407159763.
var Windows_3_0_16_1407159763 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.16 [Build: 1407159763]",
	Sign:     "Y1DuQGXo/8/rYznEGyeQHgpvZMuiCH4FYm4QVyAgLYyMpNpc/LM7XetVWhDQxGsNejkN/2olI7GVJkt4X+ooDg==",
}

// Linux_3_0_16_1407159763 is Linux 3.0.16, build 1407159763.
var Linux_3_0_16_1407159763 = ClientVersion{
	Platform: "Linux",
	Version:  "3.0.16 [Build: 1407159763]",
	Sign:     "8776GitHAgkFPfOLxEh5x+Luuh4NrYPEJUdsUzNKndcAuWMYjwQTZkmeZOeG/swdn/p2Cg2pRfZfsIFSOAUWCQ==",
}

// OSX_3_0_16_1407159763 is OS X 3.0.16, build 1407159763.
var OSX_3_0_16_1407159763 = ClientVersion{
	Platform: "OS X",
	Version:  "3.0.16 [Build: 1407159763]",
	Sign:     "vLAH2cYjkF/3sQCgr/zSmtffXcH2flI2vOnUP3uNIDSm8gKO61Q2hOdQaUzXE1yekLSMx2E9RYz+OQjQ868KAw==",
}

// Android_3_0_19_1435141265 is Android 3.0.19, build 1435141265.
var Android_3_0_19_1435141265 = ClientVersion{
	Platform: "Android",
	Version:  "3.0.19 [Build: 1435141265]",
	Sign:     "9lfj+Rx9nTpxIkhnLLubSMZQA7NcTGVxrOtz+ID4frN+1u2NVTChx9lht4RDSg58b8N6+LKIZIl8b8mIcNP6Dg==",
}

// Windows_3_0_17_1437491062 is Windows 3.0.17, build 1437491062.
var Windows_3_0_17_1437491062 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.17 [Build: 1437491062]",
	Sign:     "zlKTIfyJfjeXw9tL9MJsu5RLqKf1RrcNC+c2MQyoVwYBiSMpGJJ8KAyKtyDdK6WiKM0iIF5vjCnYBXAun9dqCw==",
}

// Windows_3_0_17_1437730067 is Windows 3.0.17, build 1437730067.
var Windows_3_0_17_1437730067 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.17 [Build: 1437730067]",
	Sign:     "JDOrqErAA93ukBMRfhI3pDqHbvIQcF9uHAJjZAlR9X1/1aESp9TDwatFAXqXF78OJA9EI+E5XTheL+BjXTwHCA==",
}

// Windows_3_0_17_1438160323 is Windows 3.0.17, build 1438160323.
var Windows_3_0_17_1438160323 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.17 [Build: 1438160323]",
	Sign:     "TtQjq217fCW3emP2G6VECMsXRWsMyt8RDs1u7iPUlRUJvGN86REPvCRBnnF3T0nwfVsqqct40qxtLzhkkYwLCg==",
}

// Windows_3_0_17_1438246387 is Windows 3.0.17, build 1438246387.
var Windows_3_0_17_1438246387 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.17 [Build: 1438246387]",
	Sign:     "K+aWgISXjmTdJYXD/lW9du+RAz3ss/3nMQeUhHK1mHEKKiPe9pI+uizi+yXSj3B4bKFOzTpmrUayHVO3aSL9Dg==",
}

// Windows_3_0_17_1438673913 is Windows 3.0.17, build 1438673913.
var Windows_3_0_17_1438673913 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.17 [Build: 1438673913]",
	Sign:     "znDjHvCgmQF/jQKTK49X8tnXqF7AGXfS2XYcogww4XxNTBxp2tf1aFc/jgboKco9EuVa0ku2cf/xg9wW3Cm7AQ==",
}

// Windows_3_0_18_1441371697 is Windows 3.0.18, build 1441371697.
var Windows_3_0_18_1441371697 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.18 [Build: 1441371697]",
	Sign:     "7uMCLHsNLl9pqL8m7foMBh4qsQZQ84eumhqWW7+A75WbQWFfN9XQ0f2UUEMzDQxbbLwWFuIO8XkzI90LbLG+Aw==",
}

// Windows_3_0_18_1442498553 is Windows 3.0.18, build 1442498553.
var Windows_3_0_18_1442498553 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.18 [Build: 1442498553]",
	Sign:     "NTcB2oaqPYbZRFSIccNpPHr39SysqffsBRS+AmYicYxUhSj9lO1NWsRTLF9fQOyaCP3m+DAfUZfRgSG3Atv/Dw==",
}

// Windows_3_0_18_1442913547 is Windows 3.0.18, build 1442913547.
var Windows_3_0_18_1442913547 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.18 [Build: 1442913547]",
	Sign:     "qBdVDaq6KdRBago4oxqd2E2vnepEu+/i1s6nSPfQm+3Wyd6gwmOomFrU7vNR0cmqu4fPvyWb9CnfYJmqPheHAQ==",
}

// Windows_3_0_18_1442998335 is Windows 3.0.18, build 1442998335.
var Windows_3_0_18_1442998335 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.18 [Build: 1442998335]",
	Sign:     "vUgm8mJoeVLBG6qB2HcYF7YNG4D+H/4edILaZbHze2Unua6mrBvNmbtRkRtmRyDZSd7sVQHMApinRDgGT1mUBw==",
}

// Windows_3_0_18_1_1444491275 is Windows 3.0.18.1, build 1444491275.
var Windows_3_0_18_1_1444491275 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.18.1 [Build: 1444491275]",
	Sign:     "xqfa3CUd2GFiTqjJWYzcu9ZbxVVLng8qIMKlVxMqWdiM8JrTRiXBAaTBDd8Xc+flVe+rGSIOZTkXRsz1rqjiAA==",
}

// Windows_3_0_19_1445263695 is Windows 3.0.19, build 1445263695.
var Windows_3_0_19_1445263695 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19 [Build: 1445263695]",
	Sign:     "z2CS87ly6Z6AHMVfs4UjhL+xobHbr/QcjjvudTL7mfrfSwe4Bm0pBaoWw+xlo8Qvtkk1OQeYjZxwUXJOJJ1wDQ==",
}

// Windows_3_0_18_2_1445512488 is Windows 3.0.18.2, build 1445512488.
var Windows_3_0_18_2_1445512488 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.18.2 [Build: 1445512488]",
	Sign:     "F0hY25Dtja0wcU6dzC39rNuYbhnDAbIwPHC3VO9Oicf13kUY2I2g6scPZ3p195Cw9gUYdBIRYm8ucHEhtSeWCw==",
}

// Linux_3_0_18_2_1445512488 is Linux 3.0.18.2, build 1445512488.
var Linux_3_0_18_2_1445512488 = ClientVersion{
	Platform: "Linux",
	Version:  "3.0.18.2 [Build: 1445512488]",
	Sign:     "W9sU8xDfWZ+eQryTdNxXVXM5Ak81wJpYKDLOiJoJUuEXoxcPnKBWpTr5JPrUzheQvkUYUIJf6WzgGAG2B7GYCg==",
}

// OSX_3_0_18_2_1445512488 is OS X 3.0.18.2, build 1445512488.
var OSX_3_0_18_2_1445512488 = ClientVersion{
	Platform: "OS X",
	Version:  "3.0.18.2 [Build: 1445512488]",
	Sign:     "hRZrg1T+25VXJffJoM9hV1qPe90HHrjbuHJM4SOj2QIasS+5bFSgzZ50/zus7Yzj8ZUovPWwn7B7WwdyiU29BQ==",
}

// IOS_3_0_18_2_1445516611 is iOS 3.0.18.2, build 1445516611.
var IOS_3_0_18_2_1445516611 = ClientVersion{
	Platform: "iOS",
	Version:  "3.0.18.2 [Build: 1445516611]",
	Sign:     "TEC965pHLJhoiNA2N95xBjQfh2n6uasS3BRFraucFv/+WgAKCKeoUYb3tu6feO5zvTEEiH6YCsedQdhbU1FFCw==",
}

// Android_3_0_20_2_1445517273 is Android 3.0.20.2, build 1445517273.
var Android_3_0_20_2_1445517273 = ClientVersion{
	Platform: "Android",
	Version:  "3.0.20.2 [Build: 1445517273]",
	Sign:     "fp6DjpIL/GlTmI3o2QEhwnXUj/pY7OFvZVPbtFBizI2Rloqm+8i0jG8Iwk05ZBn1bDOF6acPzHjBwZgl8CeWAg==",
}

// Android_3_0_21_1449476724 is Android 3.0.21, build 1449476724.
var Android_3_0_21_1449476724 = ClientVersion{
	Platform: "Android",
	Version:  "3.0.21 [Build: 1449476724]",
	Sign:     "X/xPOfXLC8ycGeWMlBc5zbyjQdBj7gYFVaSfG95gcZLoNijUaWDkB8DiqBfDvmef2JgmF8YdKTdmwjUm2n5MCw==",
}

// Windows_3_0_19_1455611032 is Windows 3.0.19, build 1455611032.
var Windows_3_0_19_1455611032 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19 [Build: 1455611032]",
	Sign:     "oFIR1O/nAb4DYuJFlHQ+KgpljBKdle59E4+iNSneNp6RmhGc/I2W/sUIkkjPOlnWO/7SVCGG+KRzmQPrlvggCA==",
}

// Windows_3_0_19_1457598290 is Windows 3.0.19, build 1457598290.
var Windows_3_0_19_1457598290 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19 [Build: 1457598290]",
	Sign:     "FNmch2Flbwd+UFBd5i8obSRyV4MZlAjYsljWzklqWFOE+exiYYJqYGH2mT7+CmaxwJkzVHlggykRMIuwj9wTAA==",
}

// Windows_3_0_19_1459504131 is Windows 3.0.19, build 1459504131.
var Windows_3_0_19_1459504131 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19 [Build: 1459504131]",
	Sign:     "JoHyZHF4k/a3+QH1zPNSEzc40487fzbpssyRZtoWB5kbQorAJgwlpcScA08J4vjGoUbdaTZsT0vCw56wo/Q9Ag==",
}

// Linux_3_0_19_1459504131 is Linux 3.0.19, build 1459504131.
var Linux_3_0_19_1459504131 = ClientVersion{
	Platform: "Linux",
	Version:  "3.0.19 [Build: 1459504131]",
	Sign:     "48s6oiT+4yKVJPsEzbPUZ2L2LqrKJ0bixxVmTFjS5f5EsfDFbD8bl7t3V+OQd84bgN7t8W80B/fjEW45IszpAg==",
}

// Windows_3_0_19_1_1461588969 is Windows 3.0.19.1, build 1461588969.
var Windows_3_0_19_1_1461588969 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19.1 [Build: 1461588969]",
	Sign:     "KYo52MA89dowkYpFU1KixgHngjbJ6F2Yi++5tbaqBlBpz9YikX2gI3sqmU1kP1ghsKCLKM7o0patDH1hv9bmAg==",
}

// OSX_3_0_19_1_1461588969 is OS X 3.0.19.1, build 1461588969.
var OSX_3_0_19_1_1461588969 = ClientVersion{
	Platform: "OS X",
	Version:  "3.0.19.1 [Build: 1461588969]",
	Sign:     "J4cWj2v28tC/8uRqXB1nnAQPfFngOFE/E4Yx7uKMY+Cb8csFrhsJW4J8i+t3dpvZeMJ0BJnB0a/dZ1iL4zh1Dw==",
}

// Android_3_0_23_1463662487 is Android 3.0.23, build 1463662487.
var Android_3_0_23_1463662487 = ClientVersion{
	Platform: "Android",
	Version:  "3.0.23 [Build: 1463662487]",
	Sign:     "RN+cwFI+jSHJEhggucIuUyEteWNVFy4iw0QDp3qn2UzfopypFVE9BPZqJjBUGeoCN7Q/SfYL4RNIRzJEQaZUCA==",
}

// Windows_3_0_20_1465542546 is Windows 3.0.20, build 1465542546.
var Windows_3_0_20_1465542546 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.20 [Build: 1465542546]",
	Sign:     "vDK31sOwOvDpTXgqAJzmR1NzeUeSDG9dLMgIz5LCX+KpDSVD/qU60mzScz9tuc9AsLyrL8DxHpDDO3eQD+hYCA==",
}

// Windows_3_0_19_2_1466597785 is Windows 3.0.19.2, build 1466597785.
var Windows_3_0_19_2_1466597785 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19.2 [Build: 1466597785]",
	Sign:     "sDOzu7rCGb7kBID2WbBk35DjPijKkXzujnsAtLhXxhkQ+am0JlDOpuU1ISHhq9gCl/Qo0dzc723o0AIPI+yoCQ==",
}

// Windows_3_0_19_3_1466672534 is Windows 3.0.19.3, build 1466672534.
var Windows_3_0_19_3_1466672534 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19.3 [Build: 1466672534]",
	Sign:     "a1OYzvM18mrmfUQBUgxYBxYz2DUU6y5k3/mEL6FurzU0y97Bd1FL7+PRpcHyPkg4R+kKAFZ1nhyzbgkGphDWDg==",
}

// Windows_3_0_19_4_1468491418 is Windows 3.0.19.4, build 1468491418.
var Windows_3_0_19_4_1468491418 = ClientVersion{
	Platform: "Windows",
	Version:  "3.0.19.4 [Build: 1468491418]",
	Sign:     "ldWL49uDKC3N9uxdgWRMTOzUuiG1nBqUiOa+Nal5HvdxJiN4fsTnmmPo5tvglN7WqoVoFfuuKuYq1LzodtEtCg==",
}

// Linux_3_0_19_4_1468491418 is Linux 3.0.19.4, build 1468491418.
var Linux_3_0_19_4_1468491418 = ClientVersion{
	Platform: "Linux",
	Version:  "3.0.19.4 [Build: 1468491418]",
	Sign:     "jvhhk75EV3nCGeewx4Y5zZmiZSN07q5ByKZ9Wlmg85aAbnw7c1jKq5/Iq0zY6dfGwCEwuKod0I5lQcVLf2NTCg==",
}

// OSX_3_0_19_4_1468491418 is OS X 3.0.19.4, build 1468491418.
var OSX_3_0_19_4_1468491418 = ClientVersion{
	Platform: "OS X",
	Version:  "3.0.19.4 [Build: 1468491418]",
	Sign:     "Pvcizdk3HRQMzTLt7goUYBmmS5nbAS1g2E6HIypLU+9eXTqGTBLim0UUtKc0s867TFHbK91GroDrTtv0aMUGAw==",
}

// Windows_3_1_1471417187 is Windows 3.1, build 1471417187.
var Windows_3_1_1471417187 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1471417187]",
	Sign:     "Vr9F7kbVorcrkV5b/Iw+feH9qmDGvfsW8tpa737zhc1fDpK5uaEo6M5l2DzgaGqqOr3GKl5A7PF9Sj6eTM26Aw==",
}

// Windows_3_1_1472203002 is Windows 3.1, build 1472203002.
var Windows_3_1_1472203002 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1472203002]",
	Sign:     "0HO60MuQm1Emn+G+ai8aJWFwcFF/y032y8pnoFGSgtMZE8RfuEmb+epDHoXlSHVwHaWy6pAafU5GvzAtKmFTDQ==",
}

// Windows_3_1_1475158080 is Windows 3.1, build 1475158080.
var Windows_3_1_1475158080 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1475158080]",
	Sign:     "jVCy5/F04fJ1aFFiHPXClAwNNHy9V9VcQP/b4kwPBTs242hqt4hyeK8kw/iFnTBtvdE44lv7ug4exrrXAh6jDQ==",
}

// Linux_3_1_1475158080 is Linux 3.1, build 1475158080.
var Linux_3_1_1475158080 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1 [Build: 1475158080]",
	Sign:     "G0j7r7DswTMF+Fuqroy6/BR+tn02AOy0IZPlg9ZIW6r2m79yudZgrbm1TB4XoUpiFfex3ImdjOQnaFRQPONpBg==",
}

// Windows_3_1_1476372595 is Windows 3.1, build 1476372595.
var Windows_3_1_1476372595 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1476372595]",
	Sign:     "RFV+pRwf2vMW/uflREuz0PE1K4J/EnuGq36DSggBF6wCjNmLv4IHokyb4rN16LW/EWZ8ny1zZrfdp9oRtb99Cg==",
}

// Linux_3_1_1476372595 is Linux 3.1, build 1476372595.
var Linux_3_1_1476372595 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1 [Build: 1476372595]",
	Sign:     "rJDhRKN4NZhUZDVVK33cIvBrxCyc/UT4casQfBAkD8c6ZgL0J48BYIRPnGGAauwZyJtEyJieuZUiMRrZ1t6WCw==",
}

// Windows_3_1_1476720122 is Windows 3.1, build 1476720122.
var Windows_3_1_1476720122 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1476720122]",
	Sign:     "Vvypi6dNQifos6pVSYKx5tQJSS/fyx4/3N8RWLnoLqSqrOiwepc4pLd3F+mafm+dSC996FQNNATGDPGPxsB/Bg==",
}

// Linux_3_1_1476720122 is Linux 3.1, build 1476720122.
var Linux_3_1_1476720122 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1 [Build: 1476720122]",
	Sign:     "q5nPwQYNVpRIHr3kIjDECqgI55XRRjJnwuSQF7oNDO19KObGUtLiOpvnH70/5lQV/LnTW+Y8MOAep3UF4gRuBA==",
}

// Windows_3_1_1478701553 is Windows 3.1, build 1478701553.
var Windows_3_1_1478701553 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1478701553]",
	Sign:     "6M7zXboPykVY5FP1LFeDho+BtAoWXKiT5gyIzRxm/Ht8BY+dVFTLEnGrzEFwHEjo8ux0ZVAE9uEwqVCEcvYMCQ==",
}

// Linux_3_1_1478701553 is Linux 3.1, build 1478701553.
var Linux_3_1_1478701553 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1 [Build: 1478701553]",
	Sign:     "BDP8PGSwrXJjyZAX2FUPnII72ovKOO12cr0B17cUS7Kvueuk5xRi6cC7q+sz8yOOV/+JIDB/RZix3mkSeAVdBw==",
}

// Windows_3_1_1480583762 is Windows 3.1, build 1480583762.
var Windows_3_1_1480583762 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1480583762]",
	Sign:     "IGq93SEt29FgghlMGD290LEsWBxQ7gW+qZy9Qok1xUiWGsxVSivYrtJ37V9jCA5pSAD3XOXui64+6cLiUN5LAA==",
}

// Linux_3_1_1480583762 is Linux 3.1, build 1480583762.
var Linux_3_1_1480583762 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1 [Build: 1480583762]",
	Sign:     "4TE9KGToLdye1zZzEz1OSjF2lsSRJUtcRB00nNvdSrhNCJmpyuSyTu1NSJxLnOud56B9MF2z2EQo4E99rRqBDQ==",
}

// IOS_3_1_1481641346 is iOS 3.1, build 1481641346.
var IOS_3_1_1481641346 = ClientVersion{
	Platform: "iOS",
	Version:  "3.1 [Build: 1481641346]",
	Sign:     "SDH0QNTA1wDQdfIU0HbcRugD3qkkPHnvlSq/IeW/I4A2myFQnDbzm8ilEGR0vOU4NoTae8CH5XsBmRqwyPIeBA==",
}

// Windows_3_1_1481795005 is Windows 3.1, build 1481795005.
var Windows_3_1_1481795005 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1 [Build: 1481795005]",
	Sign:     "3TpZZM0V+PKHELFnsfRPoKjEFfvfHUL/6mUP5LHbI3nvmdOjRqEEKi4ndXZG6OpWOKQ3VeadHDH0KBfD8EI2Cg==",
}

// Linux_3_1_1481795005 is Linux 3.1, build 1481795005.
var Linux_3_1_1481795005 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1 [Build: 1481795005]",
	Sign:     "xpJQcdaIImbctnJw0PnLQOIZBcmN+HDGcjxoIW8So7SSdSYLyUI5lAECWaCewbYmNKqaO85YqXPiNXfOBM5fBA==",
}

// Android_3_1_0_1481889010 is Android 3.1.0, build 1481889010.
var Android_3_1_0_1481889010 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.0 [Build: 1481889010]",
	Sign:     "eH8svg9XpltTbw+UYkQ4ixfqpbEAhwO9nmDDUWuI11swEU3Ye5HKGlFv70LxHZSgYlEqEH/N1J9U4ygptbPIDg==",
}

// Windows_3_1_0_1_1484223040 is Windows 3.1.0.1, build 1484223040.
var Windows_3_1_0_1_1484223040 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.0.1 [Build: 1484223040]",
	Sign:     "oaaorJ4co/sS2m5JT5oRiu9AieW6kfFY+RENqPfp26iP4pbWbf9GcZj+JhDA+/JyLpfueCcSulZSRRbash2JCw==",
}

// Linux_3_1_0_1_1484223040 is Linux 3.1.0.1, build 1484223040.
var Linux_3_1_0_1_1484223040 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.0.1 [Build: 1484223040]",
	Sign:     "xWfxm14Vw53mTMHuzeaIM428KkoI/2wuoR4O2TIuy2Q7ZpwaN48vG0rMJbUQNVycP8rRHg+bIGuFiJai8f5dDg==",
}

// Windows_3_1_1_1486051051 is Windows 3.1.1, build 1486051051.
var Windows_3_1_1_1486051051 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.1 [Build: 1486051051]",
	Sign:     "41Ed+R6kN3IRMzxd55wiGjKlz0Kj5txi2j/K/fO86dbE16sTTWU60/5Qom61p0OzjKXn8rSptl+2q+838lKVCg==",
}

// Linux_3_1_1_1486051051 is Linux 3.1.1, build 1486051051.
var Linux_3_1_1_1486051051 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.1 [Build: 1486051051]",
	Sign:     "UvsdbWQht3KHW2bdgfSYsh25G2091NE5MK4qbhmajLt2+v8ikreJGfnEsVACn54htHKhp59SnJTWly9m3c1yCg==",
}

// Windows_3_1_1_1486485240 is Windows 3.1.1, build 1486485240.
var Windows_3_1_1_1486485240 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.1 [Build: 1486485240]",
	Sign:     "CZIC/dYL5ntRZZKoa5OFf6sJUU+Fh7nyI2dSegOxoLO0kJTkVVp8FZ23j/gOKvFZZyToQRkmNvHnBAYbp9XsCA==",
}

// Linux_3_1_1_1486485240 is Linux 3.1.1, build 1486485240.
var Linux_3_1_1_1486485240 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.1 [Build: 1486485240]",
	Sign:     "NAyvIAYKfS8I/e8zug/XXg8XEbjjFJQ7CjRFaBQKLoPF7W8GfTXqGzFdIRmllg9GLYKm93kEf+dCFNzkLIagAQ==",
}

// Windows_3_1_1_1486712038 is Windows 3.1.1, build 1486712038.
var Windows_3_1_1_1486712038 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.1 [Build: 1486712038]",
	Sign:     "sryyx++NhRWKDAo+Tnwv9N+IrOaQBP0XjjDszY0BBv0YIMr4jmdHtgrwzWkUqhU7kfql7qBWIhlb/r0l1ZHeBw==",
}

// Linux_3_1_1_1486712038 is Linux 3.1.1, build 1486712038.
var Linux_3_1_1_1486712038 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.1 [Build: 1486712038]",
	Sign:     "umeERdZkG9pS3oeJTirnYK9Q947j8lVlszz2VXBPcjhQrsiKFM6lIkbj3K2HSqA/hJ+sUOcuZgo880PmU6ZdCw==",
}

// Windows_3_1_1_1_1487668590 is Windows 3.1.1.1, build 1487668590.
var Windows_3_1_1_1_1487668590 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.1.1 [Build: 1487668590]",
	Sign:     "CchjMitGiVGfRlGph0D1mDjOCJCnkVxR/WuYvNHdPyeQUCncRWML8jYxYfnhRF6CzViwYRnsmZkN+W5oenB2CQ==",
}

// Linux_3_1_1_1_1487668590 is Linux 3.1.1.1, build 1487668590.
var Linux_3_1_1_1_1487668590 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.1.1 [Build: 1487668590]",
	Sign:     "0B4RK2WOu5w39+CLznQtaexYeNqqBwU9YHBvSLw3bu+OAne8XtFc2NJzepjynrxwc1/xsmrm8uEZJzqzF+TcAg==",
}

// OSX_3_1_1_1_1487668590 is OS X 3.1.1.1, build 1487668590.
var OSX_3_1_1_1_1487668590 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.1.1 [Build: 1487668590]",
	Sign:     "WrETtyinA18FGhiDC458SwfGDozCnM+euEDmCeyC1YgQnfaEC49FtoVAbw2fry/daonzgxmyNBymVHhoUX5iDA==",
}

// Android_3_1_0_2_1487778817 is Android 3.1.0.2, build 1487778817.
var Android_3_1_0_2_1487778817 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.0.2 [Build: 1487778817]",
	Sign:     "vX2nNdYEMnwAZ2wAOAp0hsDhg099qaLv5r/rzNrfAMpXfI3JnTU7bhPxAZIh7qGk3+Geh7ffuefwoHBQRoThAQ==",
}

// Windows_3_1_2_1489662774 is Windows 3.1.2, build 1489662774.
var Windows_3_1_2_1489662774 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.2 [Build: 1489662774]",
	Sign:     "5Aaj21gGFtrjW9424ezfLa1SMQBpZvgQgcJLZmrLoNMe4XebBPV2s8rxEDAIodfFpruLxLFbFpH63A/BGnJyDw==",
}

// Linux_3_1_2_1489662774 is Linux 3.1.2, build 1489662774.
var Linux_3_1_2_1489662774 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.2 [Build: 1489662774]",
	Sign:     "W9TgKEviDgWvrQErw8vaoQcPboaUx8xRL5MPoQzlur9eO2yseHgvzkpWGYqSQyCI+ptcCpTHaXRFym0imKnfBA==",
}

// OSX_3_1_2_1489662774 is OS X 3.1.2, build 1489662774.
var OSX_3_1_2_1489662774 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.2 [Build: 1489662774]",
	Sign:     "571chpoaq6bxLisThXfiU3zB7pU0NOmH/Qso8ABTR0TXmcK9Y16pYwmPFs/d7fmcHVeI3xSM4dbgzKjRSB61Dg==",
}

// Windows_3_1_3_1490279472 is Windows 3.1.3, build 1490279472.
var Windows_3_1_3_1490279472 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.3 [Build: 1490279472]",
	Sign:     "7RPY2bzJmMdgVX24VuKD3lTnYYb6yHWqfn2x21tFOjXL9q+2t7tU9Vy8Bh5/IpeiqklUHTWc23mWpYOCoW9eCA==",
}

// Linux_3_1_3_1490279472 is Linux 3.1.3, build 1490279472.
var Linux_3_1_3_1490279472 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.3 [Build: 1490279472]",
	Sign:     "Y1M2TQvKLGmUSP4YPuTBQOeUxmF+jaqazFXuN4v2gOKP8QmxyYOsg9PsG9z7SFYQkgneQxs8QdzC+IGo0bOWBQ==",
}

// Android_3_1_2_1490288199 is Android 3.1.2, build 1490288199.
var Android_3_1_2_1490288199 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.2 [Build: 1490288199]",
	Sign:     "ODB8HVKiqknnIIhKVxhz/YoO6cbm08FFSohoDyTSR8/PQBAkSccjKWCXHgBIlml+nxJ4dOBs94+HBXfDHUQFDA==",
}

// IOS_3_1_2_1490291439 is iOS 3.1.2, build 1490291439.
var IOS_3_1_2_1490291439 = ClientVersion{
	Platform: "iOS",
	Version:  "3.1.2 [Build: 1490291439]",
	Sign:     "mTC8yRgh04oHF3jKleXVy5324ysJKp2LQIUhWh85MXqPTjh9CD0pgiUIoTuCzDQTNutAzRefcLVwniaIhNCnAw==",
}

// Windows_3_1_4_1491993378 is Windows 3.1.4, build 1491993378.
var Windows_3_1_4_1491993378 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.4 [Build: 1491993378]",
	Sign:     "rwdyEwnJCzbVfNCqbxMrRyhL5BSYqYSzKQkeZ6m5KImc1F8VB8wEkwwwyxoG7SimC/sxIyy4h27CjBFP6rcgBQ==",
}

// Linux_3_1_4_1491993378 is Linux 3.1.4, build 1491993378.
var Linux_3_1_4_1491993378 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.4 [Build: 1491993378]",
	Sign:     "wJPx0S2Q2S8EgSEpZhu+Yp80d6xVQDX5u9DYgm7XxI7sh7gJIoBbdaE5cfjwR2UN6XFyV+V/2AV4stB3CxtgCQ==",
}

// OSX_3_1_4_1491993378 is OS X 3.1.4, build 1491993378.
var OSX_3_1_4_1491993378 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.4 [Build: 1491993378]",
	Sign:     "JSg4RcthTCvJUSXTLhrmdPt1592Nk1lG9AuXg+yIyOBL6tlb030+hXniu/QrI2NeNHAMYxTJgZyi+rTnu6sFCQ==",
}

// Android_3_1_3_1_1493128735 is Android 3.1.3.1, build 1493128735.
var Android_3_1_3_1_1493128735 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.3.1 [Build: 1493128735]",
	Sign:     "Me2oMSfwCsCCGsBtgDTy+TCidslmK66JxQVR2qFsKv0v6izk6o7jzuPIFdL8Fo4rVegdCyuXPbzmOPe9j71YCQ==",
}

// Windows_3_1_5_1496989945 is Windows 3.1.5, build 1496989945.
var Windows_3_1_5_1496989945 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.5 [Build: 1496989945]",
	Sign:     "vCK7AxxVis7dQyEy5dwV3+ctSX3RUudj6OoQLW0AUDkYzkr1zp17srD6BQNZUBpaQRCQJqqDsCT4dYIpxt1vDQ==",
}

// Linux_3_1_5_1496989945 is Linux 3.1.5, build 1496989945.
var Linux_3_1_5_1496989945 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.5 [Build: 1496989945]",
	Sign:     "874htNIqcKQfggAbYrkm3OaJAaqIgWmdqKxQUpi+g1+2+aFf9Uxb407ikxG6p2Pgnk8v9Oo/chpX7E7ZCUvfBw==",
}

// Windows_3_1_5_1497432760 is Windows 3.1.5, build 1497432760.
var Windows_3_1_5_1497432760 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.5 [Build: 1497432760]",
	Sign:     "9yBvw4TOcihVsVlN37Gf3bV4EF1nyLMbcq5E+7WbootiDC+GNEA8oDRSeGadHhquf/B4G2CIDhhvjYW/X6+rAg==",
}

// Linux_3_1_5_1497432760 is Linux 3.1.5, build 1497432760.
var Linux_3_1_5_1497432760 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.5 [Build: 1497432760]",
	Sign:     "xbASm01EnV14LfoXSPARGULDZRzsn8aqQkkGuHv3efXKc4hDCVOcFglYFi/aDbLc/KkAJlHo0WEvXZHNOXlcCg==",
}

// Windows_3_1_4_2_1498644101 is Windows 3.1.4.2, build 1498644101.
var Windows_3_1_4_2_1498644101 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.4.2 [Build: 1498644101]",
	Sign:     "WtscrpvJG13kbF6aoVzsGwQuE/WwR1b8++ydDc8IpmiXLw+zFC6zFUvLinOeE0zZgh2Hs5Amp3DZoPJSynOWBg==",
}

// Linux_3_1_4_2_1498644101 is Linux 3.1.4.2, build 1498644101.
var Linux_3_1_4_2_1498644101 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.4.2 [Build: 1498644101]",
	Sign:     "Rv3SzHDwLIkuUqySQhn279jf2b7PPzCQH2q53zHWH5qyFL/Qw4m/n7ZrXEF46/sUSpOPFPYjfKMKcN/9IRCoCQ==",
}

// OSX_3_1_4_2_1498644101 is OS X 3.1.4.2, build 1498644101.
var OSX_3_1_4_2_1498644101 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.4.2 [Build: 1498644101]",
	Sign:     "MMVozpqhiRqPHFu+skm8ftODA2waeWJx2trAx205schgiJMz+H4KOLfoa92Fjrn8kAQZxpA3krUro/iBpJYkBw==",
}

// Windows_3_1_5_1498740787 is Windows 3.1.5, build 1498740787.
var Windows_3_1_5_1498740787 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.5 [Build: 1498740787]",
	Sign:     "iL8prlQuMXIMBJrszzjyPa7k36GA9DsyVEOg5L9uoK/EFc5lXH4Pv6TYj4yPZt3p6cd8OMkPfuHfXj5bn8fpDg==",
}

// Linux_3_1_5_1498740787 is Linux 3.1.5, build 1498740787.
var Linux_3_1_5_1498740787 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.5 [Build: 1498740787]",
	Sign:     "pMgKa82Qhu+5V/S7EWv0+sChqG3Hcy8k5cp1EN6TG2wiZWZAoWR2GLC5CW4+SS4fRUrLADnR+PaEjB46N3T0Dw==",
}

// Windows_3_1_5_1499699899 is Windows 3.1.5, build 1499699899.
var Windows_3_1_5_1499699899 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.5 [Build: 1499699899]",
	Sign:     "muYzth+vZLUobeluM0GMW/U59T34gn70zVpvnIyT5ADWlcsRQ3Ex0t2iqz0yTqcgn7/e0wAmqS3OLL2ctFT3DQ==",
}

// Linux_3_1_5_1499699899 is Linux 3.1.5, build 1499699899.
var Linux_3_1_5_1499699899 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.5 [Build: 1499699899]",
	Sign:     "cdnb57y0GEtvwgHoubRU9f27CEeoA4iho0JuAzmdFrTArFrFSlI9kGKuypVgjKGhv/+HcVzDCj/ncM8X567xDQ==",
}

// Windows_3_1_5_1500360741 is Windows 3.1.5, build 1500360741.
var Windows_3_1_5_1500360741 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.5 [Build: 1500360741]",
	Sign:     "0mCCWSFXyuWqKLM95/b/8seOCljvFCuupu5tst6G7hzTWQlPIdlsypdnEW+uN7XJwKacdQ3axHEmiTo6GpcXAQ==",
}

// Linux_3_1_5_1500360741 is Linux 3.1.5, build 1500360741.
var Linux_3_1_5_1500360741 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.5 [Build: 1500360741]",
	Sign:     "lCOva9P9UYmAUw1s6je2f8/44GQjj1ijeK7PadhYCY+oJp9nu1gy/MVD5xAkIuYwuJlOhac3JeBg8XdEOUAMDQ==",
}

// Windows_3_1_5_1500537355 is Windows 3.1.5, build 1500537355.
var Windows_3_1_5_1500537355 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.5 [Build: 1500537355]",
	Sign:     "O9WqHB9oX0qe9AXIYmJm0+mzl6VLxNvrGF0lGlovLaig5MXUIwd6T00NkCj62OkBbzM3eECs9FUuJk7N8V0dCg==",
}

// Linux_3_1_5_1500537355 is Linux 3.1.5, build 1500537355.
var Linux_3_1_5_1500537355 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.5 [Build: 1500537355]",
	Sign:     "Ea/9gUeh5HuXyiOZ+gRDPOn0rDHzXDVSYB70qy/BtczJPZn/0dDwQgRAF7/W6vHcaH67j+IF9AtUpuDCA6yzBw==",
}

// OSX_3_1_5_1500537355 is OS X 3.1.5, build 1500537355.
var OSX_3_1_5_1500537355 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.5 [Build: 1500537355]",
	Sign:     "oiS3ROFEy4r7zhkmCuj4cro2kIwntHNpuTFpFB+zV+AkfwX3Y2F51/JJPWG0J63tPR82n3ot/JiDkJqPKBJpDg==",
}

// Windows_3_1_6_1502264952 is Windows 3.1.6, build 1502264952.
var Windows_3_1_6_1502264952 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.6 [Build: 1502264952]",
	Sign:     "3l3IQ5y4PHAMro9/i2UqBT7xGZUE7sUcyjqWdhG+5AYhnVC5GuHnv4l44TtPneEcxWIYXFtoFlr2rlPhFwrkCw==",
}

// Linux_3_1_6_1502264952 is Linux 3.1.6, build 1502264952.
var Linux_3_1_6_1502264952 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.6 [Build: 1502264952]",
	Sign:     "P5cZgEH0ZHNdWRHLnXVwIe3xUB1jTqP3ptwqLkTqdA1d8maBliXF4uWVXYvcWF8vG10zhksMiHuhsf/v62L7Cg==",
}

// Android_3_1_6_1502275280 is Android 3.1.6, build 1502275280.
var Android_3_1_6_1502275280 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.6 [Build: 1502275280]",
	Sign:     "sEg1lt9N9lck/Kub6/N6kffI28dEsTrybGLsLc/MeWWfZ/t3EoVwwqCcBxEbUZyszx1htnbnWbd/dYBcrjSCCw==",
}

// Windows_3_1_6_1502873983 is Windows 3.1.6, build 1502873983.
var Windows_3_1_6_1502873983 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.6 [Build: 1502873983]",
	Sign:     "73fB82Jt1lmIRHKBFaE8h1JKPGFbnt6/yrXOHwTS93Oo7Adx1usY5TzNg+8BKy9nmmA2FEBnRmz5cRfXDghnBA==",
}

// Linux_3_1_6_1502873983 is Linux 3.1.6, build 1502873983.
var Linux_3_1_6_1502873983 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.6 [Build: 1502873983]",
	Sign:     "o+l92HKfiUF+THx2rBsuNjj/S1QpxG1fd5o3Q7qtWxkviR3LI3JeWyc26eTmoQoMTgI3jjHV7dCwHsK1BVu6Aw==",
}

// OSX_3_1_6_1502873983 is OS X 3.1.6, build 1502873983.
var OSX_3_1_6_1502873983 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.6 [Build: 1502873983]",
	Sign:     "ELteM70OI6OkQ6hjOr1m1ZXxDtOeCI7pqO2ce7+Sw7CoUgKlqxreTKVSlHpD7XfCEuqo3AdNfxWUNAaBci3DDA==",
}

// IOS_3_1_6_1502881949 is iOS 3.1.6, build 1502881949.
var IOS_3_1_6_1502881949 = ClientVersion{
	Platform: "iOS",
	Version:  "3.1.6 [Build: 1502881949]",
	Sign:     "DXVaZKOza0ivNdKG66VPD/g+TYwio6XmJlCfralcUIpJuh3PI4ZgAnjxzXONzTmgFm0O/rb2iN/vvxIYwhcqAQ==",
}

// Windows_3_1_7_1507896705 is Windows 3.1.7, build 1507896705.
var Windows_3_1_7_1507896705 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.7 [Build: 1507896705]",
	Sign:     "Iks42KIMcmFv5vzPLhziqahcPD2AHygkepr8xHNCbqx+li5n7Htbq5LE9e1YYhRhLoS4e2HqOpKkt+/+LC8EDA==",
}

// OSX_3_1_7_1507896705 is OS X 3.1.7, build 1507896705.
var OSX_3_1_7_1507896705 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.7 [Build: 1507896705]",
	Sign:     "iM0IyUpaH9ak0gTtrHlRT0VGZa4rC51iZwSFwifK6iFqciSba/WkIQDWk9GUJN0OCCfatoc/fmlq8TPBnE5XCA==",
}

// OSX_3_1_7_1510583507 is OS X 3.1.7, build 1510583507.
var OSX_3_1_7_1510583507 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.7 [Build: 1510583507]",
	Sign:     "OmMyxPhOHzkVKzOmy8U8CivSF/c3f8bYMhdAPLHVM6k2Ws69IzMUntr/yilFw4w6hni6Bz/Gd8Swe1L2YqCtCg==",
}

// OSX_3_1_7_1512049856 is OS X 3.1.7, build 1512049856.
var OSX_3_1_7_1512049856 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.7 [Build: 1512049856]",
	Sign:     "CRpQYBwQr5L0vU9os6s/U8e1X7kvGAnc8iUQ67TKxywSwH7cfPRooLCTOVtevt6g0Xs2O+C1t/DS7wzyOHmHDw==",
}

// OSX_3_1_7_1512141423 is OS X 3.1.7, build 1512141423.
var OSX_3_1_7_1512141423 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.7 [Build: 1512141423]",
	Sign:     "PP+/cBUDtSyV0k7lm8aYvYWAs28KL+KmXa+f0pUpDqjQDKy8dnDzJp16F4YGJxJ+2ODGPkp5YQYwts3m8T7+CA==",
}

// Windows_3_1_7_1512391926 is Windows 3.1.7, build 1512391926.
var Windows_3_1_7_1512391926 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.7 [Build: 1512391926]",
	Sign:     "n2Ntx8GVlLGTmMCILg4QbXkMA9CI5FTSfa3LcrOsz07pK4FEPHa3u8eOD0g9rFMdmQSia4jYyMDWR1KomIkRAg==",
}

// Android_3_1_7_1512665843 is Android 3.1.7, build 1512665843.
var Android_3_1_7_1512665843 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.7 [Build: 1512665843]",
	Sign:     "J04O7RCgM3ZlecpZz5H8IgWggyCJQB5KG4/MEEB5/mrW6XJEK4J5IpU3jKztkvy54B8Nrj9tbwMaRujZfILSAg==",
}

// Windows_3_1_7_1513163251 is Windows 3.1.7, build 1513163251.
var Windows_3_1_7_1513163251 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.7 [Build: 1513163251]",
	Sign:     "tdNngCAZ1ImAf7BxJzO4RXv5nBRsUERsrSOnMKVUFNQg6BS4Bzag0RFgLVzs2DRj19AC8+q5cXgH+5Ms50mTCA==",
}

// Linux_3_1_7_1513163251 is Linux 3.1.7, build 1513163251.
var Linux_3_1_7_1513163251 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.7 [Build: 1513163251]",
	Sign:     "/j5TZqPuOU8yMYPdGehvijYvU74KefRrKO5sgTUrkpeslNFiy4XfU7quKW0diLHQoPQn1t3KArdfzOAMk8dlAg==",
}

// OSX_3_1_7_1513163251 is OS X 3.1.7, build 1513163251.
var OSX_3_1_7_1513163251 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.7 [Build: 1513163251]",
	Sign:     "41eIdGPhullYi9ofXewHPXf232ZbepovkYsmR3Kc4CPlA5d/K599m5BZYBYwSz1/YfKvbTzzg0VE0FRbhcZmBQ==",
}

// Windows_3_1_8_1516099541 is Windows 3.1.8, build 1516099541.
var Windows_3_1_8_1516099541 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.8 [Build: 1516099541]",
	Sign:     "nwdwhrNjGH5IhaNoYGpJOKl0jsSYmq5f6jb0Y7ETfNNf+NqF6djEd6grCUlR7moKnkFdpRFazFsZD3E+dze9Bg==",
}

// Windows_3_1_8_1516349129 is Windows 3.1.8, build 1516349129.
var Windows_3_1_8_1516349129 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.8 [Build: 1516349129]",
	Sign:     "scnT3q9ViDVUSKceKSPQ4p50He1m0tlT9FsxSj8YMLfOoh50SKbqZEzrRTJ1aGwsGYb8x88JhjdlhDBRPhwhCQ==",
}

// Linux_3_1_8_1516349129 is Linux 3.1.8, build 1516349129.
var Linux_3_1_8_1516349129 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.8 [Build: 1516349129]",
	Sign:     "d7zSAZK8UBKLhZBl/QBSXpSOnKuSDOIG5dybmJumkO8gnH0jHvpdSblyVoj4r5J6A8V00ocp26Y9U7mo16qQCA==",
}

// OSX_3_1_8_1516349129 is OS X 3.1.8, build 1516349129.
var OSX_3_1_8_1516349129 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.8 [Build: 1516349129]",
	Sign:     "T4Ml4baqYyBOZYpt1XjxNDfkqe1iSZQoeCsMQqxVvvv45yifliizwe+5hkddsctxwY3Q1P1+/iTiW+Log5DvBg==",
}

// Windows_3_1_8_1516614607 is Windows 3.1.8, build 1516614607.
var Windows_3_1_8_1516614607 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.8 [Build: 1516614607]",
	Sign:     "gDEgQf/BiOQZdAheKccM1XWcMUj2OUQqt75oFuvF2c0MQMXyv88cZQdUuckKbcBRp7RpmLInto4PIgd7mPO7BQ==",
}

// Linux_3_1_8_1516614607 is Linux 3.1.8, build 1516614607.
var Linux_3_1_8_1516614607 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.8 [Build: 1516614607]",
	Sign:     "LJ5q+KWT4KwBX7oR/9j9A12hBrq5ds5ony99f9kepNmqFskhT7gfB51bAJNgAMOzXVCeaItNmc10F2wUNktqCw==",
}

// OSX_3_1_8_1516614607 is OS X 3.1.8, build 1516614607.
var OSX_3_1_8_1516614607 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.8 [Build: 1516614607]",
	Sign:     "93J+FDUbtRjonzFnQpGdgN6+o4jwI2M65zEKftQILCdZlGHGfc7z5Z9+TM6nU0/pnPgTqvKmaw9WYPsh88iCCA==",
}

// Android_3_1_8_1516718352 is Android 3.1.8, build 1516718352.
var Android_3_1_8_1516718352 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.8 [Build: 1516718352]",
	Sign:     "XUoyBlHsOy13YVXlfDIAGsVEiBvxpAtnK8tU+jljrSoCQMCk7GqkYmwse/t9FG8tWVP+EkO5MUNunp6NXYjOBg==",
}

// Android_3_1_8_1516865456 is Android 3.1.8, build 1516865456.
var Android_3_1_8_1516865456 = ClientVersion{
	Platform: "Android",
	Version:  "3.1.8 [Build: 1516865456]",
	Sign:     "sG/qsKb9iZpBRXFSYY2Tuq7ZLUKHcmgA/6Qe/cx35L3risqoH4aGkPkDicuKtaQi8Ikh4IrQz6xe7V49M+8VBg==",
}

// IOS_3_1_8_1516887927 is iOS 3.1.8, build 1516887927.
var IOS_3_1_8_1516887927 = ClientVersion{
	Platform: "iOS",
	Version:  "3.1.8 [Build: 1516887927]",
	Sign:     "pdWyIOpTWECIdA2NExrjqY1a7Q0alFyU7MgiDJYdiUXAspusOHwMIcfKm7oAh+Ty2gcgVgOh8wAPyZcKFKYXBA==",
}

// OSX_3_1_9_1520246719 is OS X 3.1.9, build 1520246719.
var OSX_3_1_9_1520246719 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.9 [Build: 1520246719]",
	Sign:     "gTeib0sqVKETwmYTAD6rrzgmqDHE/smMgOPTiuHPj6218mgPkhWuRWAE8pD+gm3cLMBfRl/2XlllMViYbok0DQ==",
}

// OSX_3_1_9_1520591856 is OS X 3.1.9, build 1520591856.
var OSX_3_1_9_1520591856 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.9 [Build: 1520591856]",
	Sign:     "3Kf8a0ShGCPKCnSREnJe40BxQ/jBPoBx2qFM5JDYHsQPPsL1sg5seapmMBdYoqMnkYYK5IHN0eSkrnwzXTPpAg==",
}

// OSX_3_1_9_1521637641 is OS X 3.1.9, build 1521637641.
var OSX_3_1_9_1521637641 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.9 [Build: 1521637641]",
	Sign:     "XljC4PFgstQBBbk1dPwGWSVK4eGIJCURlbONVTkGsatSXhDqfNdpLabDbEkxc1FTjcnNUAzNwDG3rn7uiFZ1AQ==",
}

// OSX_3_1_9_1523609596 is OS X 3.1.9, build 1523609596.
var OSX_3_1_9_1523609596 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.9 [Build: 1523609596]",
	Sign:     "ZtO4KjCcr1J/+ENQdwao8kheUQkcIhOahr0MmnToGRoUtVpVdXVLYn3esU2i3rG6XLLpfTU7lWUAhlWw6G3kDg==",
}

// Windows_3_1_9_1525442084 is Windows 3.1.9, build 1525442084.
var Windows_3_1_9_1525442084 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.9 [Build: 1525442084]",
	Sign:     "2SLjPTFXM9hQyNkeEGYIzs0fkBffyhsh5z+ZuaCcZdDfM8vgRM5lrAU6KNspFjLddcvw8cXw6gxRY73ZHsRVBg==",
}

// Linux_3_1_9_1525442084 is Linux 3.1.9, build 1525442084.
var Linux_3_1_9_1525442084 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.9 [Build: 1525442084]",
	Sign:     "wBcnfNU7FA0CvFeisKhywZWzmUqD6IBFbYQTveMvxWowXUjWwNHTg9tbRLQ1YgBFDdlOwV36VMX7aAMXMX2rAA==",
}

// OSX_3_1_9_1525442084 is OS X 3.1.9, build 1525442084.
var OSX_3_1_9_1525442084 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.9 [Build: 1525442084]",
	Sign:     "WVaMmYPig4eG2JUM8cMMW2MA7+IoRoPUSr74CPe7oS8TLHGjYxPr1FP88op6YsFFQrPJysWmIsnGR7BiFXjHCQ==",
}

// Windows_3_1_10_1528537615 is Windows 3.1.10, build 1528537615.
var Windows_3_1_10_1528537615 = ClientVersion{
	Platform: "Windows",
	Version:  "3.1.10 [Build: 1528537615]",
	Sign:     "+/BWvueikGg4YkO1v2uuZB5vtJJgUZ5bL8cRfxAstfnCVdro2ja+4a+8rGUzDx8/vvTZOUVD6U95hnWb638MCQ==",
}

// Linux_3_1_10_1528537615 is Linux 3.1.10, build 1528537615.
var Linux_3_1_10_1528537615 = ClientVersion{
	Platform: "Linux",
	Version:  "3.1.10 [Build: 1528537615]",
	Sign:     "jEfjYy09JfbJPZ+W3fwqygOu8uuc5raYTGpbJ5F8dHLHpqUfvmCyJVKoXRieMNkmPzeiylsUc9/HiV+8bt8tDw==",
}

// OSX_3_1_10_1528537615 is OS X 3.1.10, build 1528537615.
var OSX_3_1_10_1528537615 = ClientVersion{
	Platform: "OS X",
	Version:  "3.1.10 [Build: 1528537615]",
	Sign:     "AJMF6gyw5DBtzAuW7aA7YcZaLIgOHFappwzWtE+0UUMYgMjMkSZ1LewDaW3YyRDHuLG5Nb7X26VNhFNZu+ohBw==",
}

// Windows_3_2_0_1530183207 is Windows 3.2.0, build 1530183207.
var Windows_3_2_0_1530183207 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1530183207]",
	Sign:     "6LYlvxFIPCVnYmmFd64H8SRmxsX+y3IZOe9ju8PbZLI5j2K7ni6Z0BfEyhVprYP9VA5o4bXVrV+uNbdGSKnjCQ==",
}

// Windows_3_2_0_1530280071 is Windows 3.2.0, build 1530280071.
var Windows_3_2_0_1530280071 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1530280071]",
	Sign:     "c2M9CuucssLhQVIoye9KapFVYK7CGs1xAb6ugYivrYYs6AqkxTPP006macLaQjCrVeKTJoJN0xS+swGQMfj5BA==",
}

// Windows_3_2_0_1530790120 is Windows 3.2.0, build 1530790120.
var Windows_3_2_0_1530790120 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1530790120]",
	Sign:     "hs7X6QfM1zdlKKCY2GwMpAEe3/joZqWT8hPdNj2cBRNM4zEP/V4A6nNRtQNwNbaRpWhbqdNK5Zk3c2DkKy10DA==",
}

// Android_3_2_0_1530859847 is Android 3.2.0, build 1530859847.
var Android_3_2_0_1530859847 = ClientVersion{
	Platform: "Android",
	Version:  "3.2.0 [Build: 1530859847]",
	Sign:     "pjvK4iy+bB5X90mQI/Rzbkes27EokJjSOoGSXCqpjuPFj8Pe6BXt3M2E9VH/1Ec2hf8h51mr3D+cycGQpHq+DA==",
}

// Windows_3_2_0_1531390529 is Windows 3.2.0, build 1531390529.
var Windows_3_2_0_1531390529 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1531390529]",
	Sign:     "OLjamtIbU0PxYhLtSQrYbi1yhZZrJbGAGQJFNtZ4DZ2Ae2eeudQWY2Y8r0T27rLNckdyFqPydX0PrxKHxnZ6CQ==",
}

// Windows_3_2_0_1531481279 is Windows 3.2.0, build 1531481279.
var Windows_3_2_0_1531481279 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1531481279]",
	Sign:     "Y74ib4ayZCVp7el+ou1X1k5qCjRf8Vg9zX3ACqbH7jtIricC4Mhds11uvhE7MNa5ZWPOU6OPrHmLlMW8+tgvCw==",
}

// OSX_3_2_0_1531481279 is OS X 3.2.0, build 1531481279.
var OSX_3_2_0_1531481279 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.0 [Build: 1531481279]",
	Sign:     "VlxQyIng/96p9Kvag2U0epcVFQUubJ+cVMUUxut+rHh6znj3k0NPL/c9/vwxqOXwsCueebiOIEjieOzaPv2tAg==",
}

// Windows_3_2_0_1532529142 is Windows 3.2.0, build 1532529142.
var Windows_3_2_0_1532529142 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1532529142]",
	Sign:     "GtYKBlk8a+tse8WnBVE9XPxg4fHVnscQ6GEQGMyG8MQbZYLHw7dwEAEmtQ6ygWerwETUVKxG+qNfGWZAF5/IAA==",
}

// Windows_3_2_0_1533289185 is Windows 3.2.0, build 1533289185.
var Windows_3_2_0_1533289185 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1533289185]",
	Sign:     "757W7J3m6dYThNzDTLZzHfbU1bxqcKyTqjZT8OOZj+GQsyvrUhZhBe961sTqH1zZaNYuzNKyzeIXL+pAS9iGCw==",
}

// Windows_3_2_0_1533739581 is Windows 3.2.0, build 1533739581.
var Windows_3_2_0_1533739581 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.0 [Build: 1533739581]",
	Sign:     "TJ1XoCjQz+VxW15qiGInWf5llTBtVu+2m2ShbY0/HWTM7adLyfThq7wzSgr09Fvowibvu91nOFxTlIpPXCAVAQ==",
}

// Linux_3_2_0_1533739581 is Linux 3.2.0, build 1533739581.
var Linux_3_2_0_1533739581 = ClientVersion{
	Platform: "Linux",
	Version:  "3.2.0 [Build: 1533739581]",
	Sign:     "Vt+iPp952TU4uKwGXY0L61mXgBNfXg+1+16fnS0snPU9fhkfOKzdPN4rBELOwJ5XzZc33KdVC8rzZGYzlQceBg==",
}

// OSX_3_2_0_1533739581 is OS X 3.2.0, build 1533739581.
var OSX_3_2_0_1533739581 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.0 [Build: 1533739581]",
	Sign:     "WkySbYMiHN22ra3Y1cktHyeNikQ4fZ0K++8brc+8ImYhuzrmuzeGwL+QNaPJNty7stTNCfRUSpDzVAWz5TYQCA==",
}

// Windows_3_2_1_1534255236 is Windows 3.2.1, build 1534255236.
var Windows_3_2_1_1534255236 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.1 [Build: 1534255236]",
	Sign:     "RtNOb2UrlXwwy3lplxRilvknygxamwb3eKlRRAsG5YjrMEikStl/Sf+oJgFUFBBMSJ+q+xPx3+xfOmMxAkB8Bg==",
}

// Linux_3_2_1_1534255236 is Linux 3.2.1, build 1534255236.
var Linux_3_2_1_1534255236 = ClientVersion{
	Platform: "Linux",
	Version:  "3.2.1 [Build: 1534255236]",
	Sign:     "betw82OYRNjyhXDHmmUKwR6xfvyPHBMdkn+jukQKNG8PPLKOfLFb0OAMXPZxp9n8gio840gFowwA/jnbg/OMBw==",
}

// OSX_3_2_1_1534255236 is OS X 3.2.1, build 1534255236.
var OSX_3_2_1_1534255236 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.1 [Build: 1534255236]",
	Sign:     "AWbZhd8XH+s7uu5Qkb2QkdDcc9/WXfNu2iKWD+e6m2oTrOmI1Jt55SsyDTvkpBpumnWsrtR/GI2nK9HbmFhGAw==",
}

// Android_3_2_0_1534407950 is Android 3.2.0, build 1534407950.
var Android_3_2_0_1534407950 = ClientVersion{
	Platform: "Android",
	Version:  "3.2.0 [Build: 1534407950]",
	Sign:     "rY2Hhki/5tJZW5YyJI6S9o9zuU4IGFpONwR6JBJ3Q7Pukfj08z2brFwCmGR61RzH8IaoPxoAWXIHQoHp6fUABQ==",
}

// IOS_3_2_0_1534410132 is iOS 3.2.0, build 1534410132.
var IOS_3_2_0_1534410132 = ClientVersion{
	Platform: "iOS",
	Version:  "3.2.0 [Build: 1534410132]",
	Sign:     "BIWgZdgGSu6yPwCiEDQuORaLRqV1Z17ZLcxYdLqM2hfWXiKwBOO/j5eH4IH7LGubFfDwdGcVW2RUYKATpaJAAA==",
}

// Android_3_2_1_1535010120 is Android 3.2.1, build 1535010120.
var Android_3_2_1_1535010120 = ClientVersion{
	Platform: "Android",
	Version:  "3.2.1 [Build: 1535010120]",
	Sign:     "HHlJgd/XKWFdPOR5N4n2hpsjZ3y5b+4f4x1tLk397GI+gcALWlehtQDSaxe2R975/dFcEWmHiFd9zSC3tsecDA==",
}

// Windows_3_2_2_1535010838 is Windows 3.2.2, build 1535010838.
var Windows_3_2_2_1535010838 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.2 [Build: 1535010838]",
	Sign:     "ZUdctNEUa/SrRrXbqFCESmKIVDJj0nJrO0vwvxDNJGB/p65vf5GqvX9p625FOXO50dxxHPIIAvJDEjM/TxeuBg==",
}

// Linux_3_2_2_1535010838 is Linux 3.2.2, build 1535010838.
var Linux_3_2_2_1535010838 = ClientVersion{
	Platform: "Linux",
	Version:  "3.2.2 [Build: 1535010838]",
	Sign:     "7uY1DWoJD2x80002ha6jSkNRXGcfHAqS9hdJz80JjafvhmxlhQKSwfsofFjEq10TI8LFbhLdv7TQxd+gPyNEAg==",
}

// OSX_3_2_2_1535010838 is OS X 3.2.2, build 1535010838.
var OSX_3_2_2_1535010838 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.2 [Build: 1535010838]",
	Sign:     "qvbU2yq0wzSxPLPClraVmriM1Z+yB9qq5UzQ+gxuwE6dG8k/eosJH9xBhL7bhgcJKRgY2vsL00vbiLk19c+rBA==",
}

// Windows_3_2_2_1535459906 is Windows 3.2.2, build 1535459906.
var Windows_3_2_2_1535459906 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.2 [Build: 1535459906]",
	Sign:     "ErpAeuVpXF2IMeqeCTdoaKLEKSbQkquGlr/QsohLnxwcqdW3ltuPXofu+nJRK8IgRRyDfockqDOHSSud8hRYCg==",
}

// OSX_3_2_2_1535459906 is OS X 3.2.2, build 1535459906.
var OSX_3_2_2_1535459906 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.2 [Build: 1535459906]",
	Sign:     "+aKFdPYAhzafs+eBAfjYn0v4lVlIEK0Eq/KLT8qwI04/bZ/OYw7eQyioABDQXMpE/7PVt/jt7/AzlYWJikZeBQ==",
}

// Android_3_2_2_1536327256 is Android 3.2.2, build 1536327256.
var Android_3_2_2_1536327256 = ClientVersion{
	Platform: "Android",
	Version:  "3.2.2 [Build: 1536327256]",
	Sign:     "dwHJuheBuCMZlUGz2N+DeyoWokK9/ui0CCV6HE4yJ6fqjoyFIyuX9TqXho63tNKXDa0XscL1U4TOaJlgU6pWDQ==",
}

// Windows_3_2_2_1536584091 is Windows 3.2.2, build 1536584091.
var Windows_3_2_2_1536584091 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.2 [Build: 1536584091]",
	Sign:     "z63aqvx/q/R/SAsO/OcYl3duuj/RuDswghIxI7MlttMqvEuYIQQrHU92kn7TkrnbOlaVCe0F+RFrilckcPlUBQ==",
}

// IOS_3_2_2_1536587534 is iOS 3.2.2, build 1536587534.
var IOS_3_2_2_1536587534 = ClientVersion{
	Platform: "iOS",
	Version:  "3.2.2 [Build: 1536587534]",
	Sign:     "4rsRo3H9Uw0kui/cQkaBiqYy8ox6/gC6jDUVktcB6I71m1TeqUYy/IYMYbNSBtv0bmKntvcA0ZU79+zoXUkSAg==",
}

// Windows_3_2_2_1536915823 is Windows 3.2.2, build 1536915823.
var Windows_3_2_2_1536915823 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.2 [Build: 1536915823]",
	Sign:     "aBGFNFtVk/dmfk8cEecxKYreB4ht0LmpFBr86R90kj+1MFjSTevzaJTNywm+oS1hru5VM09Mzlk+k/8JFtWGDQ==",
}

// Windows_3_2_2_1537178465 is Windows 3.2.2, build 1537178465.
var Windows_3_2_2_1537178465 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.2 [Build: 1537178465]",
	Sign:     "LHJV3O+hoZZlKWDPKH4ZMCoPUarYWwnaUgfMP+Xdm/4sY5NYUYjkVQaU4FS4pqxii5jx6O4cFToG7ekFB53NBA==",
}

// Linux_3_2_2_1537178465 is Linux 3.2.2, build 1537178465.
var Linux_3_2_2_1537178465 = ClientVersion{
	Platform: "Linux",
	Version:  "3.2.2 [Build: 1537178465]",
	Sign:     "P2NaVyWrk5AkG1KE8hTPCT6J0ql0NzLeeII4BF3WarfVjDbekqKu2sQfO7W3OSJKN3cH8w5470csP4LZ+hrkAA==",
}

// OSX_3_2_2_1537178465 is OS X 3.2.2, build 1537178465.
var OSX_3_2_2_1537178465 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.2 [Build: 1537178465]",
	Sign:     "QbSOeAPhPHgZKykNbEAlzGLZe8w+ulxcZXbk07wOBGLK/vWCfQlyIDPUK5DipGBUfRY9yJvxfUx7g9b5dU8aBw==",
}

// Android_3_2_3_1537790492 is Android 3.2.3, build 1537790492.
var Android_3_2_3_1537790492 = ClientVersion{
	Platform: "Android",
	Version:  "3.2.3 [Build: 1537790492]",
	Sign:     "qLdDfrZyNIdl1pDYtyrGbOLZK/Yi/i8PE/a7QOInsEa5/RBz+HW8EBGPvazz+lLZbHrBXyp875NyrKtLnc4dDg==",
}

// Android_3_2_4_1537790492 is Android 3.2.4, build 1537790492.
var Android_3_2_4_1537790492 = ClientVersion{
	Platform: "Android",
	Version:  "3.2.4 [Build: 1537790492]",
	Sign:     "cJVVnQRoUWsYSaYKWZ/sIGAAMTpnBDFu8T6shyH5o9AXWLVyu2qRmVVuyvKmMSlEVlYNtVrHIlC2AHtq3l2nDg==",
}

// Windows_3_2_3_1538467030 is Windows 3.2.3, build 1538467030.
var Windows_3_2_3_1538467030 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.3 [Build: 1538467030]",
	Sign:     "dZ1i/CsCaAh4F7Pi2F/FfaBpdTmUuNVsAIRnqm86FUR3HhwBRn+xlmbwRF8gObgFMuwFMCLmawncFWplSILKAQ==",
}

// Linux_3_2_3_1538467030 is Linux 3.2.3, build 1538467030.
var Linux_3_2_3_1538467030 = ClientVersion{
	Platform: "Linux",
	Version:  "3.2.3 [Build: 1538467030]",
	Sign:     "pEBdtUvRUmczMmHZM5xmeZuiRP/Kb/H2YShNKGpaat8aPTmG5EF+zsbjUFNWW4tnt43Yard0bWDUsrJ9/mmjBQ==",
}

// OSX_3_2_3_1538467030 is OS X 3.2.3, build 1538467030.
var OSX_3_2_3_1538467030 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.3 [Build: 1538467030]",
	Sign:     "yr8F54NuExnwarhvcJ27f3LvDop1wqwrhyqEVvpliRKi0hLD3e+cW2mJWRkq0eDjPRQ2kzPvBst9yNH1MsuYAQ==",
}

// IOS_3_2_3_1538494750 is iOS 3.2.3, build 1538494750.
var IOS_3_2_3_1538494750 = ClientVersion{
	Platform: "iOS",
	Version:  "3.2.3 [Build: 1538494750]",
	Sign:     "YgRxbZGpaxVAPuC3bln8HiCdgyx8EgM37H+VCSjZnn+05+lo1w74P9LFHSVqr1NBuB5YtKNWp0xjHRbBZVJtDQ==",
}

// Windows_0_0_1_1543011433 is Windows 0.0.1, build 1543011433.
var Windows_0_0_1_1543011433 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1543011433]",
	Sign:     "0yUT1LLSAOTAMPiBGOAq6lUPnXv2N49clNjQ8MSmhNQmI2lFP1LT4Vo3XTuZ0QX5IBQBxnB9nJooV2Te11HhAA==",
}

// Windows_0_0_1_1543414034 is Windows 0.0.1, build 1543414034.
var Windows_0_0_1_1543414034 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1543414034]",
	Sign:     "MoJT06d4BNOJrTlC9EnTi74rpu2rv8TKvXck1FlpNfB1IQO2DgZpHPjQbcpMnkstYFd6WBWVJvM2GAr71K+VAw==",
}

// Windows_0_0_1_1549019113 is Windows 0.0.1, build 1549019113.
var Windows_0_0_1_1549019113 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1549019113]",
	Sign:     "N/GCBSNBRQUruUvJ+YM8IxeH+W+OkafgefmerruLOqrD9PRtFQ6WLvQA8rY/egFZPJ0Lu4dfaTDJ8UPLtS4xDQ==",
}

// Linux_0_0_1_1549639384 is Linux 0.0.1, build 1549639384.
var Linux_0_0_1_1549639384 = ClientVersion{
	Platform: "Linux",
	Version:  "0.0.1 [Build: 1549639384]",
	Sign:     "iyFuMGDAoSE8LnZuV+ezxQ0iP1dgY/4FB9yZIe2emUnS/go5HA9zx945Clwi7zO/U5xgTLGxBQvDD/IONLS+BQ==",
}

// OSX_0_0_1_1549657968 is OS X 0.0.1, build 1549657968.
var OSX_0_0_1_1549657968 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1549657968]",
	Sign:     "8usYZFvBvzaRRLu7EWPT4k3/7Ikhhla/Q53Q/qzxBPH4E3LoJFg1OH+IirFlTNze518j/Qx2ZyJ2RS1oHrAWCA==",
}

// Windows_0_0_1_1549713549 is Windows 0.0.1, build 1549713549.
var Windows_0_0_1_1549713549 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1549713549]",
	Sign:     "OgAHgZJmuhL/SMIbmWzGNqvJ47cOAWHSVAcYDxTJswU/B6zzEDD+kB711uqlyFH9JDZb1tbzbi45+NlcMwlJCA==",
}

// Linux_0_0_1_1549713549 is Linux 0.0.1, build 1549713549.
var Linux_0_0_1_1549713549 = ClientVersion{
	Platform: "Linux",
	Version:  "0.0.1 [Build: 1549713549]",
	Sign:     "7XvKmrk7uid2ixHFeERGqcC8vupeQqDypLtw2lY9slDNPojEv//F47UaDLG+TmVk4r6S0TseIKefzBpiRtLDAQ==",
}

// OSX_0_0_1_1549713549 is OS X 0.0.1, build 1549713549.
var OSX_0_0_1_1549713549 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1549713549]",
	Sign:     "xNaB5RLET+B+Y02CirR0S+qEKUqwhgQqOAbg3QHDeekc1bl+bJ68FDJUW0LZ5ewY23Vrm5LtXpRCloKIoDUrBA==",
}

// Windows_0_0_1_1549829683 is Windows 0.0.1, build 1549829683.
var Windows_0_0_1_1549829683 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1549829683]",
	Sign:     "Tx/cUfXAdy+xB+X9e3o/OgwIoJf7EKWb9mxXc+a39+vNJzganUFUEoHnuRDyUJqZY4URM15/vhbyqQiDnRYHAg==",
}

// OSX_0_0_1_1549829683 is OS X 0.0.1, build 1549829683.
var OSX_0_0_1_1549829683 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1549829683]",
	Sign:     "MzkDQHfzv1nZhM3y99c4neMywQvRho2sQ7Pv+SCh0V8H1LaMB/0Ui9VkafIYhaf/gVi+I9wCvM8jDvMgVaCdDA==",
}

// OSX_0_0_1_1549895652 is OS X 0.0.1, build 1549895652.
var OSX_0_0_1_1549895652 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1549895652]",
	Sign:     "v/sgnywcuwFMKhOlpoKLLuT+6shYyY5eHVSOo9pm8EUzcpHFe5sh8Aa6EIi/Zisnkf3Nt6JrlGS5++bLV6h8Aw==",
}

// Windows_0_0_1_1549957568 is Windows 0.0.1, build 1549957568.
var Windows_0_0_1_1549957568 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1549957568]",
	Sign:     "F7f5rksW2FaFQsjRi+6Hs5fUQVqBLk+9TcKSyAxqUcwsG8pTpeb1ImfVHPLdmq0Ua5tofVeSoeGlfj2jiwVrDA==",
}

// OSX_0_0_1_1550066976 is OS X 0.0.1, build 1550066976.
var OSX_0_0_1_1550066976 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550066976]",
	Sign:     "Rau3KBAqvD8p/lm5M26r58zk0KQJjGqqKO+E7bcOLOtikJCbCrceTRATlqoxZKRjE6Ngf3LdsUtsDYab7TO0CQ==",
}

// OSX_0_0_1_1550084944 is OS X 0.0.1, build 1550084944.
var OSX_0_0_1_1550084944 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550084944]",
	Sign:     "xdv6EalStVMxsGrjJHtcaCqHlhr2OzWRiTZrDMYMmgTiorbRbzMYdrQsNw2a6E1efbuBuHs8mLIkAT4y0KJNDQ==",
}

// OSX_0_0_1_1550143598 is OS X 0.0.1, build 1550143598.
var OSX_0_0_1_1550143598 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550143598]",
	Sign:     "sQtvL4f6Z/gBf89kgv02UFHJVufDqKWcS6bPqvNMQHlSJrU/BN3HksOq1Bt4Z1fh/0NJ9la0PuUlMmKg8FAhAg==",
}

// Windows_0_0_1_1550226976 is Windows 0.0.1, build 1550226976.
var Windows_0_0_1_1550226976 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1550226976]",
	Sign:     "4jX+WqL9KZilTrNvb8Gh6sKjVYSvgAhm+HGDgioifYpszS7nPK2UJmNxKE2wAztufWGueJsD9oEvdQvG4SjIDQ==",
}

// Linux_0_0_1_1550226976 is Linux 0.0.1, build 1550226976.
var Linux_0_0_1_1550226976 = ClientVersion{
	Platform: "Linux",
	Version:  "0.0.1 [Build: 1550226976]",
	Sign:     "22vWrtMv2ObaBwrQGw2CLs2LzUQJ94KoXiVuMObXf5pfoIw2MY4ZqMt8oL9CCyQBtKl6vV3CZntLrAR25ljeDw==",
}

// OSX_0_0_1_1550226976 is OS X 0.0.1, build 1550226976.
var OSX_0_0_1_1550226976 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550226976]",
	Sign:     "kXlZanPcXrP022c7tsTaMUVCljTN4dTDHiXlGXDbtwlpqfBZvuw5k6Qm0nsUsX/lK707+2Z9xpU+WLOh3NxkDw==",
}

// Windows_0_0_1_1550255704 is Windows 0.0.1, build 1550255704.
var Windows_0_0_1_1550255704 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1550255704]",
	Sign:     "D8Ci2ZJERAKMKsIBRCPxCsHPaCFajgR30yuRlNdr+QVAHmhsKODF8Mpa/YFkYpdxwGY26UR4iUDQgiBOu09aDw==",
}

// OSX_0_0_1_1550255704 is OS X 0.0.1, build 1550255704.
var OSX_0_0_1_1550255704 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550255704]",
	Sign:     "SfFM7wo/5BA0HxKLHOqgh35LiB5HlqtmHSnCvAiUECBDlXxL8bRmTrrXvRHLUGP+4IvM9RzMbnj9/q1vcftWDg==",
}

// OSX_0_0_1_1550502842 is OS X 0.0.1, build 1550502842.
var OSX_0_0_1_1550502842 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550502842]",
	Sign:     "VfMBVc8YKYh9KpyihQz3c983AAOV83Gss+t1M4jeQ5AFl/+Kn3ZcVZQhjVFQnfWQ8RuVtagJUTTKlDs5XeJdCg==",
}

// OSX_0_0_1_1550679784 is OS X 0.0.1, build 1550679784.
var OSX_0_0_1_1550679784 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550679784]",
	Sign:     "nx9CIytTawoAJdYJo3wT+zTKD31lylYhjUpK8AN6ZpvlIQE95Fm7lkzN8qfEK9NRdG4p3rX/6oVXT+Iv53MvCg==",
}

// OSX_0_0_1_1550876871 is OS X 0.0.1, build 1550876871.
var OSX_0_0_1_1550876871 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1550876871]",
	Sign:     "hb10qtSWPUw8gSbdQDILIRgT9RRaCM0mzj4m9MQo2xLv1EYNZZD8svVsV/qrj6uTxtJ8WLS4RrOtkgm9qPC0CQ==",
}

// OSX_0_0_1_1551044658 is OS X 0.0.1, build 1551044658.
var OSX_0_0_1_1551044658 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1551044658]",
	Sign:     "b4OpbCAVsZLtkUJ5DWzH/L29v8FZN1+3Dhdi3jmrivZE1TPTdII8OoYuY5spNKJtQma8BSJHjW0XyG9YT+NqDw==",
}

// Windows_0_0_1_1551204931 is Windows 0.0.1, build 1551204931.
var Windows_0_0_1_1551204931 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1551204931]",
	Sign:     "uT/wwWZnLwO4dMIlLFYiOq1ot3p2761RNGno3KaGOKRCR7km680zdws2hmgU1lVGXTmmYdSDiKwcDQPckk+lAA==",
}

// OSX_0_0_1_1551459948 is OS X 0.0.1, build 1551459948.
var OSX_0_0_1_1551459948 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1551459948]",
	Sign:     "iz304gq0xhX0oYrgn9ehoY8Q5S7xeeMX8gBgQ7CYfrdQnWMVusl8NY7qJ0SJJRQhFo+l/FZBmGGozscluPMgAA==",
}

// Windows_0_0_1_1551711227 is Windows 0.0.1, build 1551711227.
var Windows_0_0_1_1551711227 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1551711227]",
	Sign:     "5Js/GD8nfYOfvR5Aa4ef3B3EgItH+bcQC6woFuR94yBDgQ0W8TUQ59u4GGufbjo6s4/16otHLJ48q0+Q4HptCA==",
}

// OSX_0_0_1_1551713318 is OS X 0.0.1, build 1551713318.
var OSX_0_0_1_1551713318 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1551713318]",
	Sign:     "l4lTnkGORNFQh6N3Rrm962oaeQVhKnliOYv0aLJPNCw/N2EKLMDQ2HBGdNWQSr/iWevkJUcXFQAAXy1Ql7ydAA==",
}

// Windows_0_0_1_1551783896 is Windows 0.0.1, build 1551783896.
var Windows_0_0_1_1551783896 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1551783896]",
	Sign:     "KT+SQaENLWvvIpuGY55oTqOJjhamigNWl48uutyPPJDPZEcqRAkU/lh/+wrKgOl65jsNDuJOHVOlEda8VRMzDw==",
}

// Windows_0_0_1_1552322960 is Windows 0.0.1, build 1552322960.
var Windows_0_0_1_1552322960 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1552322960]",
	Sign:     "9EU17JQJagk/elGn4Tpewc52XsL6nkeyEDgiXBgKD3hPEi+0Froo2urFyosoFaOap5x1L6lg5lf+yyBDNIX+Bw==",
}

// OSX_0_0_1_1552322960 is OS X 0.0.1, build 1552322960.
var OSX_0_0_1_1552322960 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1552322960]",
	Sign:     "rCRrdfzjZqAN8MfEm5dM0dvH5DIsTxntEEhlCI+AxNJjCgZKGnygGwXPT4unubpF0AuljnTP/as7QVbDRqf0AQ==",
}

// OSX_0_0_1_1552499895 is OS X 0.0.1, build 1552499895.
var OSX_0_0_1_1552499895 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1552499895]",
	Sign:     "OiIxmD9ntH/NHcgAImw3bR/VEDQYQR8oQMagFjjbcyQP14nDhcCGoG1Quq8Y+2q58UerHoLYV83z1Pok3zkMBQ==",
}

// Windows_0_0_1_1552572862 is Windows 0.0.1, build 1552572862.
var Windows_0_0_1_1552572862 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1552572862]",
	Sign:     "my05e2+UaIDGYec2KG72JGRRAOEqosp1kA1vaIFHuf7s2KNNNZPqh4bsnmJ2LWARQVJWFvrnnjsEwjsC7GdcBQ==",
}

// OSX_0_0_1_1552572862 is OS X 0.0.1, build 1552572862.
var OSX_0_0_1_1552572862 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1552572862]",
	Sign:     "AZ/MCSPFSY4JnB+YhexNtnp1IN71whrShaY+3q5FIBp0/CpNlsqeqZEf80Al1kK4KGdelUIQFwEKrBZDoAtHBw==",
}

// OSX_0_0_1_1552575092 is OS X 0.0.1, build 1552575092.
var OSX_0_0_1_1552575092 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1552575092]",
	Sign:     "RerNRKL0lwhRYOYBUfIcDNB95dTIQUc4OJOsXtUTZnV5b3M4WHMb8uugT6qWZhrOObzEQ9/Wk4MazMejIyk6Dw==",
}

// Windows_0_0_1_1552639727 is Windows 0.0.1, build 1552639727.
var Windows_0_0_1_1552639727 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1552639727]",
	Sign:     "kQ+MQqHTHNXXdDr7uxwU/ioX7z3mwifmG+y3iQgFO8+t6khxdG+r681nVVJbH5DWPWkp9EybR7O+tkj8VepqBA==",
}

// OSX_0_0_1_1552639727 is OS X 0.0.1, build 1552639727.
var OSX_0_0_1_1552639727 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1552639727]",
	Sign:     "dZI4OOZ920/Jz6uN3wdSY/cJBKIwYi/2Vabb/DKRI/7ne+TbMF52jHDtKR8farlOR6LKV2kgDEFfZTzPWdBIAg==",
}

// OSX_0_0_1_1552661204 is OS X 0.0.1, build 1552661204.
var OSX_0_0_1_1552661204 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1552661204]",
	Sign:     "/rsQcIITEztmEqkR529p5QZql3wX8PUHiRdD3Xj5J7qXfmIIdHqf5IplMc+zC4Kcst6mc+RSYjzA8hqq55FfAQ==",
}

// Windows_0_0_1_1552982242 is Windows 0.0.1, build 1552982242.
var Windows_0_0_1_1552982242 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1552982242]",
	Sign:     "lTI32KaoJMMowYoN4YWvzYM5A9sU9qmy2ZFQHnRxXQejwLWv96XDeYZFBBB+BbsYlD0wbWZtvSz6diJhEnAKCg==",
}

// OSX_0_0_1_1553161313 is OS X 0.0.1, build 1553161313.
var OSX_0_0_1_1553161313 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1553161313]",
	Sign:     "xiE4CVM01BoGLWxPlCBVWKzSzVFOIu4uu+1Zq1PXKzS+UIdZk+bqhqye0cHtVDwSaz6z40/4f0409K9ZcoIjCA==",
}

// Windows_0_0_1_1553512400 is Windows 0.0.1, build 1553512400.
var Windows_0_0_1_1553512400 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1553512400]",
	Sign:     "3vv71iNuOytrgxh6AN0W0fcxhe3LO+0L9CSKd+I95RzDeoFOLpb3L3v7mtY8RycWxvb9L9afpuKFn9EbXMTeBA==",
}

// OSX_0_0_1_1553512400 is OS X 0.0.1, build 1553512400.
var OSX_0_0_1_1553512400 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1553512400]",
	Sign:     "1cP6H/YKjgFj0dTlSXHOZUJQ64t7hkY23vDMEJz2A1J47KmZXGwXphNHdD3GN5Pn4IfExzA0w3X01hrBb0InDg==",
}

// OSX_0_0_1_1553695906 is OS X 0.0.1, build 1553695906.
var OSX_0_0_1_1553695906 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1553695906]",
	Sign:     "mmpn3i5p8NlBRZK84pRrVjLouHBHMNG8ajL2RSXGcK0O4Oe+fQWW10uMF+RcfEAI7JMpfCX9hI6/CFr5zRkxAg==",
}

// OSX_0_0_1_1554384958 is OS X 0.0.1, build 1554384958.
var OSX_0_0_1_1554384958 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1554384958]",
	Sign:     "KiRmVipTS+ZOMv/smwfFw7gNDoKrLMyHO5HLXT6boyo3NwpQDoOyc2UpMOmMNKZTEx9dA9uCb2q3x1SjovLjCg==",
}

// OSX_0_0_1_1554399512 is OS X 0.0.1, build 1554399512.
var OSX_0_0_1_1554399512 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1554399512]",
	Sign:     "WWVBed7WmK6eLaScLDvU/AOzi3tHaaX15VciJfSZa+maEyk9mEnGpfYSccb/25q5gKv1xjHrssoy3LDLOG20Ag==",
}

// Windows_0_0_1_1554736383 is Windows 0.0.1, build 1554736383.
var Windows_0_0_1_1554736383 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1554736383]",
	Sign:     "Wf73FFZU9xp0RgCeZUSBgR/4OTlvcdUBbSXjTxMaNMEeHH2G3vfOyb2HDoN4WgE9UDkDYeK8Lef68S2hru+zBw==",
}

// Windows_0_0_1_1554822978 is Windows 0.0.1, build 1554822978.
var Windows_0_0_1_1554822978 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1554822978]",
	Sign:     "t/BvQLC7xOtcPZ6A1StLsc9DtOw9TEii++82zrwOkEXpQk/ts2UVcYNeonNq+tSnxuPeRM7AVQQSc5KNz5I4BQ==",
}

// OSX_0_0_1_1554822978 is OS X 0.0.1, build 1554822978.
var OSX_0_0_1_1554822978 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1554822978]",
	Sign:     "GJJS+cDKE7eCzEMb8FORdSWP3iVkZ13irxGmEU/UicafIjgFIpNbcFTPCzJVCJ8TbJ+uXz5Jt2LK0wu7eGkmAQ==",
}

// Windows_0_0_1_1554918032 is Windows 0.0.1, build 1554918032.
var Windows_0_0_1_1554918032 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1554918032]",
	Sign:     "swQxkzltj92y6u94gjl8i+rUdGYtGB6eWgdbmtPRzoQ6D6Ju1SRQ0J35jxk8lpL4WRp+OkBFmeVKTsJ2n0ZnAA==",
}

// Android_3_2_5_1554991343 is Android 3.2.5, build 1554991343.
var Android_3_2_5_1554991343 = ClientVersion{
	Platform: "Android",
	Version:  "3.2.5 [Build: 1554991343]",
	Sign:     "HkOn2tmPaY8qTNhnpZl34QkmhHJzOBVuUdeANQQoCMqDyDovii5zFJnGALyuab5/bHPl9rqy1jllmhWlm34JCA==",
}

// Windows_0_0_1_1555000573 is Windows 0.0.1, build 1555000573.
var Windows_0_0_1_1555000573 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1555000573]",
	Sign:     "ss6fgeQA8LSSJpjEia5Jfh3G63JigMqCdkyqlhH7NgMzacBV/Phbcl12GcDXYlzCt/QY2xhi/ku1U+1KVD0/Ag==",
}

// Windows_0_0_1_1555015683 is Windows 0.0.1, build 1555015683.
var Windows_0_0_1_1555015683 = ClientVersion{
	Platform: "Windows",
	Version:  "0.0.1 [Build: 1555015683]",
	Sign:     "AMnbAjVfFPOWlwcEFQjz0pokTLpjGEN7TdH6HliidbMBQXLlj9T/LmwRr+IT/ZjpY9+znSXLbVmF2+d0jLRLAA==",
}

// OSX_0_0_1_1555082010 is OS X 0.0.1, build 1555082010.
var OSX_0_0_1_1555082010 = ClientVersion{
	Platform: "OS X",
	Version:  "0.0.1 [Build: 1555082010]",
	Sign:     "o/GYOMVcxtE+JWFjozRjS9FJ/h35gGcPfvZkc23AlglNXI5aj6oGg3Gin3M1fLOnSOxn3TSU5WhaQtvCYZgZDg==",
}

// MacOS_5_0_0_355a06f9_1555407897 is macOS 5.0.0-355a06f9, build 1555407897.
var MacOS_5_0_0_355a06f9_1555407897 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-355a06f9 [Build: 1555407897]",
	Sign:     "1NtwyJX2p7rkrN/hWD49iu0p43r0gnaiDY+2W2aUVyGhh5cYjPz84IxzNaR4UPs4dgFpJPJM4pdf9KivwJmGDA==",
}

// Windows_5_0_0_test_192_1555445179 is Windows 5.0.0-test-192, build 1555445179.
var Windows_5_0_0_test_192_1555445179 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test-192 [Build: 1555445179]",
	Sign:     "2qdOjcl4ZcqYyLvp6u5oHTH9LPbergYHKASwWc+Sj6iBO3Y/jSzCawuDW9/3nKzlG0lbi/JcFtyku4DN08mCDg==",
}

// MacOS_5_0_0_test_192_1555445179 is macOS 5.0.0-test-192, build 1555445179.
var MacOS_5_0_0_test_192_1555445179 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test-192 [Build: 1555445179]",
	Sign:     "e3HFhHXYOgw0BsMgkhax9sQ54BA722ZEb7W0j21k9huKC7yISTkDcrAWGCXe+pjR0mucjazMYHMzue6kJk6NDA==",
}

// MacOS_5_0_0_bf7671e7_1555448654 is macOS 5.0.0-bf7671e7, build 1555448654.
var MacOS_5_0_0_bf7671e7_1555448654 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-bf7671e7 [Build: 1555448654]",
	Sign:     "ayQ8KcWuXKoPtmjRfH7WuY3ECyPWKL4JqEals0SkgB1CNqDR/PBgryvOUxN+W8N2d38BMH7g8VkdA2XeTrzZBg==",
}

// Windows_5_0_0_test_197_1555495120 is Windows 5.0.0-test-197, build 1555495120.
var Windows_5_0_0_test_197_1555495120 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test-197 [Build: 1555495120]",
	Sign:     "MOS8hPR38S/LAoMn+R9JXVsV+cDJVAyI/Dfpvt3NYKwiis1LqdWZymu4osfcrfJGdpSg5q6YZa1CeJSETaizCQ==",
}

// MacOS_5_0_0_718a441b_1555496184 is macOS 5.0.0-718a441b, build 1555496184.
var MacOS_5_0_0_718a441b_1555496184 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-718a441b [Build: 1555496184]",
	Sign:     "y8el2L26T6NR19KOphUYNtQ0NTe39z9PGoyYGEuQUPTBk4vG/x09RmSppdIKrj9ZV4sl+hQ8y11rCi3rRQ3bAA==",
}

// Windows_3_2_5_1555517253 is Windows 3.2.5, build 1555517253.
var Windows_3_2_5_1555517253 = ClientVersion{
	Platform: "Windows",
	Version:  "3.2.5 [Build: 1555517253]",
	Sign:     "iyy+8G7ksPHvXb45ijQ9Kfr8TMsCc3sGRKJLiPArx7YMPu8YV4GgYzM4+MpuMQUTlNkU7w5B0od9IJ/7E4nDDQ==",
}

// Linux_3_2_5_1555517253 is Linux 3.2.5, build 1555517253.
var Linux_3_2_5_1555517253 = ClientVersion{
	Platform: "Linux",
	Version:  "3.2.5 [Build: 1555517253]",
	Sign:     "+nqAMBv2NxHYfPwHyRmleALMU/2gpiv1LAV6dmrLjNXaTS3BwLBVuysSuqHsuiK3/Xff0IRRFANz8qT1ztJqDQ==",
}

// OSX_3_2_5_1555517253 is OS X 3.2.5, build 1555517253.
var OSX_3_2_5_1555517253 = ClientVersion{
	Platform: "OS X",
	Version:  "3.2.5 [Build: 1555517253]",
	Sign:     "xrP7+C0BjffIZf7FD21P/xYoCSTmq8nCa3w2q3McX2DlUIEjfMLAX7uepdeiNYZfspAWJmi9QIkpQCltNBwqAg==",
}

// MacOS_5_0_0_59fc92f9_1555588817 is macOS 5.0.0-59fc92f9, build 1555588817.
var MacOS_5_0_0_59fc92f9_1555588817 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-59fc92f9 [Build: 1555588817]",
	Sign:     "p289ARagvIGDg1lknPUB07x1NUqXEN9kuMwSMKZDrO1gC0wrwAqeaMLt91uNy3VINCOjoDhBdnxMiBed4xCuDg==",
}

// Windows_3_3_0_1555590310 is Windows 3.3.0, build 1555590310.
var Windows_3_3_0_1555590310 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1555590310]",
	Sign:     "eKXdV7wEuwhoN+nk97ety2gAiNM3afKEejHNyc2slGASWXRgrorsEb8c2hcfy9D1iM/OGmsj54inilYZQz76Bw==",
}

// OSX_3_3_0_1555590310 is OS X 3.3.0, build 1555590310.
var OSX_3_3_0_1555590310 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1555590310]",
	Sign:     "4K5QbIPYfu42+ytMNgJOvYHB0kY/S+su1vsJ7zuLVlMs+XHbNhJEtjMANjDJAxfJ+fJ77VLBHf1Jo6Q5pSJFBA==",
}

// MacOS_5_0_0_ffa1a6e8_1555609180 is macOS 5.0.0-ffa1a6e8, build 1555609180.
var MacOS_5_0_0_ffa1a6e8_1555609180 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-ffa1a6e8 [Build: 1555609180]",
	Sign:     "DPJYkUdJdZVIP+92KuGAJ2ytN6Q723moxG+nFGD50s+I/0kPPEw6pz3B8vCD41mG7pp0aPCQoMBFqYgz7IfEAA==",
}

// MacOS_5_0_0_01c1042e_1555956706 is macOS 5.0.0-01c1042e, build 1555956706.
var MacOS_5_0_0_01c1042e_1555956706 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-01c1042e [Build: 1555956706]",
	Sign:     "D9odXVufvwsTsmzrCZ3iOG+zCGagT3gmori1+EWm/Q3A9jUvNiTpOxUoGNdVJ72pADeVczQldGbG44RIX8zYCg==",
}

// Windows_3_3_0_1556009531 is Windows 3.3.0, build 1556009531.
var Windows_3_3_0_1556009531 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1556009531]",
	Sign:     "dhfCi8/4JnkIh3iNPr/7HwzAlVfMgk2IXDdHpyduLZ4BiIOwILZuHVU6u8b/j46yYUklMulweujLaI3IRn7MCg==",
}

// Windows_3_3_0_1556116957 is Windows 3.3.0, build 1556116957.
var Windows_3_3_0_1556116957 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1556116957]",
	Sign:     "fOs05Nq80Wvcu8wx7MtITPrCLuKZ6kWY7rwWGYWByri4NbVpmY9mFpfzqBcB3MgnMkp/kTU2jteCjtKjI3EEBg==",
}

// MacOS_5_0_0_20262827_1556210877 is macOS 5.0.0-20262827, build 1556210877.
var MacOS_5_0_0_20262827_1556210877 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-20262827 [Build: 1556210877]",
	Sign:     "0Z+ODov6Dcu0oUuVQV8h059RbFN9+Dj+0KTRWId1GK9d2pq7IrEMzWJHI+R92KnRyaKQnOmH1RdnVzEZjeLXBw==",
}

// Windows_5_0_0_test_202_1556234251 is Windows 5.0.0-test-202, build 1556234251.
var Windows_5_0_0_test_202_1556234251 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test-202 [Build: 1556234251]",
	Sign:     "G5U66Tyy6vajlxvHMhboeLzd91lS1/o15sK1FyCBvbaETjRy78R33FvSLak2bOKwFlXecMlNf8HlhrsulJh7CQ==",
}

// OSX_3_3_0_1556290731 is OS X 3.3.0, build 1556290731.
var OSX_3_3_0_1556290731 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1556290731]",
	Sign:     "TmPMXMIBrqHO4CWg9fcPxSKG0DxxJGb6D0pLkqJUZDHJ+tOcM2e9s5ZAmTzeDPCDnq89f5pOooPa8iPEyo4yDQ==",
}

// MacOS_5_0_0_alpha203_1556295552 is macOS 5.0.0-alpha203, build 1556295552.
var MacOS_5_0_0_alpha203_1556295552 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha203 [Build: 1556295552]",
	Sign:     "DaV6Rvgau7bZng3HQr2Tt8nDffi/bNWwaBhL+OkqiUShZE2X5CPaCYix1ahZRID+XF3jANSHu7anQNgaNQ2rAQ==",
}

// Windows_5_0_0_alpha204_1556312473 is Windows 5.0.0-alpha204, build 1556312473.
var Windows_5_0_0_alpha204_1556312473 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha204 [Build: 1556312473]",
	Sign:     "liv9ymEJFPqK0x/duZzn9uJqfkL5tTq2WOn1omAMkomTef7k5wd0FQ71ioJhBAr5UU4rKceahVMVhwFrYwcQBQ==",
}

// MacOS_5_0_0_alpha204_1556312473 is macOS 5.0.0-alpha204, build 1556312473.
var MacOS_5_0_0_alpha204_1556312473 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha204 [Build: 1556312473]",
	Sign:     "R0GsDv1WkAMMACsoigLj8zXtIDieUIfVQ7Js3kNMtV2IY3EHAr/rEvG/R8OQYJjtxDQYHu09D31BxXOLabc7AQ==",
}

// Windows_5_0_0_alpha206_1556530824 is Windows 5.0.0-alpha206, build 1556530824.
var Windows_5_0_0_alpha206_1556530824 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha206 [Build: 1556530824]",
	Sign:     "Zi50u4yizVqLgbK9Zi1jM0M4AOojMXvzSk2WhOFGdtNEaz/F4KvitnDVjtu5hzYIyrHFEY472lCCjL5o/qcbCA==",
}

// Linux_5_0_0_alpha206_1556530824 is Linux 5.0.0-alpha206, build 1556530824.
var Linux_5_0_0_alpha206_1556530824 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-alpha206 [Build: 1556530824]",
	Sign:     "jIng2diWQpiV/D0tMDJSoA24IB2kB1weMJi16NdXRVKaULISROJHhbZKVZwOvl7Dm2yQFneUXguxzUE5bHWXAA==",
}

// MacOS_5_0_0_alpha206_1556530824 is macOS 5.0.0-alpha206, build 1556530824.
var MacOS_5_0_0_alpha206_1556530824 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha206 [Build: 1556530824]",
	Sign:     "AaYqqXfOM9YSHTCNw/dVBrLUx8e/Kb+m7WmcRfEOrI+gqxS+EyqINxPQxpohpf7SW3OU2p2ic3BqaR89AFCqDQ==",
}

// Windows_3_3_0_1556542489 is Windows 3.3.0, build 1556542489.
var Windows_3_3_0_1556542489 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1556542489]",
	Sign:     "VRm2iUqx3CYHIXog65jCFBZDNr4/fa6RIaItQgcfCtncrK7h/c4onUaPPH0pJZ3juwLML7xktRX4re3MoHE5Dw==",
}

// OSX_3_3_0_1556542489 is OS X 3.3.0, build 1556542489.
var OSX_3_3_0_1556542489 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1556542489]",
	Sign:     "5yXva471HNY14SB2bwv8wc204PIxZu7FRaNMFPHRbruAP5hVvuCFI15SBIas+OSOwxJKqnzYkKfxAbRci2sRCA==",
}

// Windows_5_0_0_alpha207_1556616734 is Windows 5.0.0-alpha207, build 1556616734.
var Windows_5_0_0_alpha207_1556616734 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha207 [Build: 1556616734]",
	Sign:     "qKNjBD/w6eywswACwGTRB2Y3x+je1htUDrsEhm9+G67wysTZeM8LMgcCz0V8+zTo9b5YNNC9N8aFxl8NZeQ0AA==",
}

// MacOS_5_0_0_alpha207_1556616734 is macOS 5.0.0-alpha207, build 1556616734.
var MacOS_5_0_0_alpha207_1556616734 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha207 [Build: 1556616734]",
	Sign:     "LIv/VLt/oKLDhOejNGJPQ36/7smVaUn1ChGj2FbqLSc1FJBczX/kKuGtdYAq0Qlfh3tD38NzKT9585FnFrwLBg==",
}

// Windows_3_3_0_1556630414 is Windows 3.3.0, build 1556630414.
var Windows_3_3_0_1556630414 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1556630414]",
	Sign:     "kKY5l53E4SLiSWqc00CiuCcfeNziXPLwcXDCVcACIV45tupxzCo+w+g58qP+Z5A83NoExD+50EIuOEPzK+8AAg==",
}

// OSX_3_3_0_1556630414 is OS X 3.3.0, build 1556630414.
var OSX_3_3_0_1556630414 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1556630414]",
	Sign:     "LCnJGOq+P+cY30Pn2oOOK488op2EXEun1MgeMiTXlmzj/tjuvpdrxoiXC9Vu8C97eoOBVRD4hj6fN7FODaklDA==",
}

// Windows_5_0_0_alpha208_1556660248 is Windows 5.0.0-alpha208, build 1556660248.
var Windows_5_0_0_alpha208_1556660248 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha208 [Build: 1556660248]",
	Sign:     "UTdgQaFrU15818vsU2raGj6Uy8A3jbzVY2RighZqrxC/HLlA/h4IWIbiAPE3Evxv95Cgb7Vg93ufYhpSNY8EBQ==",
}

// Windows_5_0_0_alpha209_1556801404 is Windows 5.0.0-alpha209, build 1556801404.
var Windows_5_0_0_alpha209_1556801404 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha209 [Build: 1556801404]",
	Sign:     "FhUBPJ4W9+B3Yb42X+Rw9/+hEjwZeYTnTL39h7J8WEeYBrj7ocDSsnQosz55VNleHUgLCABSn0BqG5yEJf09Dg==",
}

// Windows_5_0_0_alpha212_1556813029 is Windows 5.0.0-alpha212, build 1556813029.
var Windows_5_0_0_alpha212_1556813029 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha212 [Build: 1556813029]",
	Sign:     "hpXm9n1GJOr5eSoMKH4U6qUPHbcoGaCjCV9heCmQa8PeunGa+ka1sgAf9H8njXUxCoQQYQDKazrTnb7DnGFIBw==",
}

// MacOS_5_0_0_alpha212_1556813029 is macOS 5.0.0-alpha212, build 1556813029.
var MacOS_5_0_0_alpha212_1556813029 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha212 [Build: 1556813029]",
	Sign:     "7M9RrXON8iXKOTe1N/lVC0ZuL1HIWuFyI4kWKpnTe3EUPf9LZf/tXGzRPHD2C1ih3JXxEuVuDSd46a9rwVWcAg==",
}

// Windows_5_0_0_alpha214_1556897845 is Windows 5.0.0-alpha214, build 1556897845.
var Windows_5_0_0_alpha214_1556897845 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha214 [Build: 1556897845]",
	Sign:     "iFV4wtdkvLQPQPKtpoB4eiBNy+r0lU6hVw/C3t8ir/zgoWmuh7DaQbKu6+0Sx2zNeyg8d7AspN3ApYUWLk+5Ag==",
}

// MacOS_5_0_0_alpha214_1556897845 is macOS 5.0.0-alpha214, build 1556897845.
var MacOS_5_0_0_alpha214_1556897845 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha214 [Build: 1556897845]",
	Sign:     "37CHmojr18Zo1y0Lu1g/HjPAUvEePh5T/Iui+zcOobPJFwGgCNs4X+cVBGf9vzBOyd3qSi/CxbB1KL/VM9XNBQ==",
}

// Windows_5_0_0_alpha216_1556918526 is Windows 5.0.0-alpha216, build 1556918526.
var Windows_5_0_0_alpha216_1556918526 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha216 [Build: 1556918526]",
	Sign:     "sWDezOByhJ2GNjO5+w3oGWpI9jXXZy72iBSdSryHBMVCW3c7khfLzmpipqC/3yUACQU07yEwThcYLsK4+UYrAw==",
}

// MacOS_5_0_0_alpha216_1556918526 is macOS 5.0.0-alpha216, build 1556918526.
var MacOS_5_0_0_alpha216_1556918526 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha216 [Build: 1556918526]",
	Sign:     "UoCCR0jcJHW0z3NuQsIG1XBipDMgPiHbD7zFZVnB97Q1RgsKwRyvOBumXrAeCL/SEAprkAmrU0ofYQBuR1NjAQ==",
}

// Windows_5_0_0_alpha217_1557239244 is Windows 5.0.0-alpha217, build 1557239244.
var Windows_5_0_0_alpha217_1557239244 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha217 [Build: 1557239244]",
	Sign:     "r/rlz7JCCAVmV1FT5mhvu6plHA6Hnq50vkSd0nlgWuvZ42OtGtpklLkk+Toc3BW6f7roO8pgqbr5rKlry+KmDQ==",
}

// Windows_5_0_0_alpha218_1557333442 is Windows 5.0.0-alpha218, build 1557333442.
var Windows_5_0_0_alpha218_1557333442 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha218 [Build: 1557333442]",
	Sign:     "Smg0cmM4kCTX6Pby2dFZmqbVm/60S92m4RVUjLf2tXZ1lynNmJTKS/M0cFFRpYQhw9RHmKK6oAEz5rtKv/8bAQ==",
}

// Windows_5_0_0_alpha219_1557415390 is Windows 5.0.0-alpha219, build 1557415390.
var Windows_5_0_0_alpha219_1557415390 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha219 [Build: 1557415390]",
	Sign:     "sXLcoviMWxxPVR0+BD9Kpv0pKDBCyk3DSKZwW2AOa0YZhrfSgTXciDXbMmOgOk362OHLxcKAw1cjGgNTrh3KBw==",
}

// MacOS_5_0_0_alpha219_1557415390 is macOS 5.0.0-alpha219, build 1557415390.
var MacOS_5_0_0_alpha219_1557415390 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha219 [Build: 1557415390]",
	Sign:     "WgNuMCz2tpWDCGABKIBCT7VopmskmlVcbFM2z6ZDqPTFtmebu2iKsJ1VofMiWPknHWnllduKNW8ocvTQiJywBw==",
}

// Windows_5_0_0_alpha220_1557519031 is Windows 5.0.0-alpha220, build 1557519031.
var Windows_5_0_0_alpha220_1557519031 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha220 [Build: 1557519031]",
	Sign:     "J2z/+8j1Ls3n/f63eIhKB3IlK8vOVlw62Y9fUqUDlYNDUDWdOg4PakhvMgw26UiL419/rx0Qm6CfdjDgbU3hBQ==",
}

// MacOS_5_0_0_alpha220_1557519031 is macOS 5.0.0-alpha220, build 1557519031.
var MacOS_5_0_0_alpha220_1557519031 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha220 [Build: 1557519031]",
	Sign:     "tDngpCe+wRn+fGIxTdCg9cFBIyoSF3XYSaw7ZDmumjPDRwaNqZ7U0g1DVe6xRtoOhZczhIUM2ANAaVfhhOvGBQ==",
}

// Windows_5_0_0_alpha222_1557769659 is Windows 5.0.0-alpha222, build 1557769659.
var Windows_5_0_0_alpha222_1557769659 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha222 [Build: 1557769659]",
	Sign:     "wwbvrQ42kySxiyVqGGRajKho1yLFKfmoDiVjg5NQGUpag3lTCVn66ZS1O56nI+sfY1Yj3IwFiZbgcxbXPjBkDQ==",
}

// MacOS_5_0_0_alpha222_1557769659 is macOS 5.0.0-alpha222, build 1557769659.
var MacOS_5_0_0_alpha222_1557769659 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha222 [Build: 1557769659]",
	Sign:     "EVTuQ2+e/AXohPHoYo+VYByUjeYvP2JBy/aeYuKI912zVbrITSwG9b7JpRgAJyPUyvsLnAWKlwYA9RPtXCNIBA==",
}

// Windows_5_0_0_alpha223_1557842114 is Windows 5.0.0-alpha223, build 1557842114.
var Windows_5_0_0_alpha223_1557842114 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha223 [Build: 1557842114]",
	Sign:     "pYAtduIWDXlkr4FuGXUhNkk5lJLropb7aoY/qKABaf4GdvWpbN9KmdgbCMvSwhXWPi0+YZoVgHS81CYWkHGGDg==",
}

// MacOS_5_0_0_alpha223_1557842114 is macOS 5.0.0-alpha223, build 1557842114.
var MacOS_5_0_0_alpha223_1557842114 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha223 [Build: 1557842114]",
	Sign:     "oAgBumoab/97kQZaJTE/Nc/NrMVbM7B/G1Ob4mUMIWF8Orw9KBtDNJ8e3Hq1TQzNUBDiQ6Q4vub0OEUGld3pCA==",
}

// Windows_3_3_0_1557914437 is Windows 3.3.0, build 1557914437.
var Windows_3_3_0_1557914437 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1557914437]",
	Sign:     "Cc5W6QpqeEhSa1sODAy/pmLRZ1nA1ZsUbDhwg7H0KjWoxy6l8JWMmviXLWuA8RuDzJJVJV6bQU3Hf6QcMNlRBQ==",
}

// OSX_3_3_0_1557914437 is OS X 3.3.0, build 1557914437.
var OSX_3_3_0_1557914437 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1557914437]",
	Sign:     "+kZH9b/Ka86RnioFhD+RS8oYQHu8Ijb9vqLdySKgRY05LVU5CJtWOCQ+IrNUOYDVqMEuHzkPGDFQFO85tHhUBw==",
}

// MacOS_5_0_0_alpha224_1558094517 is macOS 5.0.0-alpha224, build 1558094517.
var MacOS_5_0_0_alpha224_1558094517 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha224 [Build: 1558094517]",
	Sign:     "g0J4+3KSC1LPYXqgzO2cwb97hCgijJnOcgvuSElBLPrnhPSyC92XQZUIkBF6AqkOtIoK1TfbpvCZOpy61d5cAA==",
}

// Windows_5_0_0_alpha225_1558176095 is Windows 5.0.0-alpha225, build 1558176095.
var Windows_5_0_0_alpha225_1558176095 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha225 [Build: 1558176095]",
	Sign:     "B37WMPFIacoScNJ4yiL/bngwZ9StFNACAJ65LezIlL1OIq+nTexacjc/qLr4oncCDzhoLCUxumsCR/bzkxESDg==",
}

// MacOS_5_0_0_alpha226_1558186695 is macOS 5.0.0-alpha226, build 1558186695.
var MacOS_5_0_0_alpha226_1558186695 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha226 [Build: 1558186695]",
	Sign:     "DTRDsFrz1JRxAoqbsIiJwL5O+dn3+RDcHaQO5KS8auxPcZPa1NFC6A7cbUlDiez1zTjWf2uuGf5ZhMcv+JZIDw==",
}

// Windows_5_0_0_alpha228_1558453482 is Windows 5.0.0-alpha228, build 1558453482.
var Windows_5_0_0_alpha228_1558453482 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha228 [Build: 1558453482]",
	Sign:     "+yW0rVsjHZNWYWZLPOrhWcdGUn8xumz2dpUS+gaJyR3hR1paxzicQq58jBmZv92MmsT2Wj3Zs+UzQf5NzHLlCw==",
}

// MacOS_5_0_0_alpha228_1558453482 is macOS 5.0.0-alpha228, build 1558453482.
var MacOS_5_0_0_alpha228_1558453482 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha228 [Build: 1558453482]",
	Sign:     "CS8WBiOC67A/vs3iHbrG7PCF1Nv5Zcde+fiqbXha1KxJKjYJKJ2BiyfuePUtpO7YL5+G1DuDZrzIg0pFYcseDA==",
}

// Windows_5_0_0_alpha229_1558545291 is Windows 5.0.0-alpha229, build 1558545291.
var Windows_5_0_0_alpha229_1558545291 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha229 [Build: 1558545291]",
	Sign:     "MS7HlWUlkp3IZDBalR9xEcGPotoXh+23QecliSQ4B+01dpz7EA4e/VqknjzZrn4ns72qauMbXT/zqUqR6zAcBA==",
}

// MacOS_5_0_0_alpha229_1558545291 is macOS 5.0.0-alpha229, build 1558545291.
var MacOS_5_0_0_alpha229_1558545291 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha229 [Build: 1558545291]",
	Sign:     "QHxI/Co5ZTPCPlvr0YBuXzoaTbJdl1XxGtJt6TjKBjE2VLjQwRm5Bx++jYY7Ff55IwUUhTZ98j0UTMwVsxVcBQ==",
}

// Windows_5_0_0_alpha230_1558630781 is Windows 5.0.0-alpha230, build 1558630781.
var Windows_5_0_0_alpha230_1558630781 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha230 [Build: 1558630781]",
	Sign:     "llzRK5eSY3jWVuHvCwoeb5Nl10YKw6Lk5F+tAt7DkUMIwEoM7U3sxFHeMf3J/yYrenAKb6FgqB6WHqXYINPoBA==",
}

// MacOS_5_0_0_alpha230_1558630781 is macOS 5.0.0-alpha230, build 1558630781.
var MacOS_5_0_0_alpha230_1558630781 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha230 [Build: 1558630781]",
	Sign:     "dCxOoelZNVXI377eBmeplmiXI8PgQUYRSk7WVnJ1cZvFQeMIEbzKHgvA5PVD1Dyj0i4FpZpucmnACglNBxY5Bg==",
}

// MacOS_5_0_0_07b4003d_1558632796 is macOS 5.0.0-07b4003d, build 1558632796.
var MacOS_5_0_0_07b4003d_1558632796 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-07b4003d [Build: 1558632796]",
	Sign:     "Bq4/nAP0mR6SYuXx3J+Qk4+UAcnqraWchH+x5GMlZ3d7qnYkysNn4WlQCEjLuO2Idayx+xdLQmq+jASWTYzPBw==",
}

// Linux_5_0_0_alpha231_1558722704 is Linux 5.0.0-alpha231, build 1558722704.
var Linux_5_0_0_alpha231_1558722704 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-alpha231 [Build: 1558722704]",
	Sign:     "3fMgWCWzh/v8A+EM45vXindYtEMS/Ofpt11eUyHntfr4algP622X9iyPfdOFJnnFH4ISAd7Qh56T2BvVlFPyBw==",
}

// MacOS_5_0_0_alpha231_1558722704 is macOS 5.0.0-alpha231, build 1558722704.
var MacOS_5_0_0_alpha231_1558722704 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha231 [Build: 1558722704]",
	Sign:     "Dndjvq5Y3GPe6IB+9BgX+RfNqzh6CmLLBxHMdXwUvbB4CE8TPqBP7gZwnYeUjf4Ij0yOSitmeJMLseHU5UcyCQ==",
}

// Windows_5_0_0_alpha232_1558967089 is Windows 5.0.0-alpha232, build 1558967089.
var Windows_5_0_0_alpha232_1558967089 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha232 [Build: 1558967089]",
	Sign:     "gzCs9to1JZ7EnKIAQ46LzsSu9VgL4fOijAvgu6dG1itUVI9ilE8WSWk6azeJQoSXXUqUhVlJEdRsjMAsSMvIBg==",
}

// Linux_5_0_0_alpha232_1558967089 is Linux 5.0.0-alpha232, build 1558967089.
var Linux_5_0_0_alpha232_1558967089 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-alpha232 [Build: 1558967089]",
	Sign:     "3T7hpgk1meh3GGXvZW72K/3uQolAUHFLKVM8RP90psN5oIwYmxFDgnAsoOIyktHUYyCdF6JqpUN6hl/yOYY7Dg==",
}

// MacOS_5_0_0_alpha232_1558967089 is macOS 5.0.0-alpha232, build 1558967089.
var MacOS_5_0_0_alpha232_1558967089 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha232 [Build: 1558967089]",
	Sign:     "PypsLXiPjW2EQkHbaUveezItfhMQQ5aonMWlpqWezfP/zoxtvUET5yf9lFY/PqO/bFtShhmPL/tXKBI3ht4qDg==",
}

// Windows_3_3_0_1558980407 is Windows 3.3.0, build 1558980407.
var Windows_3_3_0_1558980407 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1558980407]",
	Sign:     "QVrvVgvXctohZ6wGzvJFB3SnHH5TTqYHLJ0A+j4KZrpn3EKNuXpmieIjJ4NiMx+Kce2hO02FXSY/KVT4doTmCg==",
}

// OSX_3_3_0_1558980407 is OS X 3.3.0, build 1558980407.
var OSX_3_3_0_1558980407 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1558980407]",
	Sign:     "Vmf0Mq8hgly/4ChaLz3m0/RM7IwJdEXyIOljGu74lv4ZKOLHE9o2K42sCdbrtG4IPXTaBlEiItNDeFmAD4FhDw==",
}

// Linux_3_3_0_1559042453 is Linux 3.3.0, build 1559042453.
var Linux_3_3_0_1559042453 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.0 [Build: 1559042453]",
	Sign:     "U+WzCGMDh5JYkFfA7ZPDt43sZhVFW/8tHNXPeHAP+ZOK+3W0/c8TvkFiW9NR8j190KswFVYb7NOhigzXsn3jAw==",
}

// OSX_3_3_0_1559042453 is OS X 3.3.0, build 1559042453.
var OSX_3_3_0_1559042453 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559042453]",
	Sign:     "MsN0f5qqK36AtXMMP7i2yE7bXFHRST/cbB6PaD9HMDomK4q8cG5qBVIGXa7KG0PAAZUtJAXwr1c+6fCIzBJRAA==",
}

// OSX_3_3_0_1559061820 is OS X 3.3.0, build 1559061820.
var OSX_3_3_0_1559061820 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559061820]",
	Sign:     "uG9rtcA593JtA4RuwRYuSD29I1cNWa9rYub8xndRbvZ1z/qhqUk2oGwnQzeQOyzZRDzExfYiFwLLi4LGTNXADw==",
}

// OSX_3_3_0_1559143149 is OS X 3.3.0, build 1559143149.
var OSX_3_3_0_1559143149 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559143149]",
	Sign:     "JTB+B3tPBtR81UKWwPwELq7WX5SnJ8oY5yT6MyCqUAxoC82XEp7ZUYvgyuLdQ01eHNpmQNF25nyH+4+vBdeGBQ==",
}

// IOS_3_3_0_1559144369 is iOS 3.3.0, build 1559144369.
var IOS_3_3_0_1559144369 = ClientVersion{
	Platform: "iOS",
	Version:  "3.3.0 [Build: 1559144369]",
	Sign:     "xXYmjT4t0D0Oll99yVPTsRXxJuqFr4ShKEtetow7ii6Qwkm3mkMIrg67NR8foo24bBQgcY+s1CQC88CD8WT6Bg==",
}

// Windows_3_3_0_1559151651 is Windows 3.3.0, build 1559151651.
var Windows_3_3_0_1559151651 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1559151651]",
	Sign:     "R8rfsRoxzUGuHQIwPiMPeAC687o8NW3fzjA4f6Ivgn6b1JTSjAO2qguKhJfNjGl7EVFTagNManW9bSib6bkkBg==",
}

// OSX_3_3_0_1559151651 is OS X 3.3.0, build 1559151651.
var OSX_3_3_0_1559151651 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559151651]",
	Sign:     "d+imICJxJ0pW1jeHdu1+zi8P0RfgViiYRhVwSBaG39O9oWHVIriaRJKJDuqrdnjGCehX174Zyg243Ul+02AQBw==",
}

// OSX_3_3_0_1559172971 is OS X 3.3.0, build 1559172971.
var OSX_3_3_0_1559172971 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559172971]",
	Sign:     "ycEAOKlOA1FT53mQt3WHCbTOikB0KTgbtsJM2ZPnA7pV4cBbG7xJ3FS5WZd46lDDcl4RQuhwIIGNXf1JJs+VCA==",
}

// Windows_3_3_0_1559207969 is Windows 3.3.0, build 1559207969.
var Windows_3_3_0_1559207969 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1559207969]",
	Sign:     "YR+Frh2ZvoqZABO/hk0fLM5urA970HHgkNuiFCowTQkAd4n5Qv+Z9bPsjrlZF8UkIJUacX2f6yXrbEdk6fSFBw==",
}

// Linux_3_3_0_1559207969 is Linux 3.3.0, build 1559207969.
var Linux_3_3_0_1559207969 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.0 [Build: 1559207969]",
	Sign:     "rF/2IHXSOMtJrVigZ8nz1gj7AO6OUmCMkPUCvtmiPXHzopjETT+juLcclvX7jUo3nElMMxPdm1ZmQcTM2HXqAw==",
}

// OSX_3_3_0_1559207969 is OS X 3.3.0, build 1559207969.
var OSX_3_3_0_1559207969 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559207969]",
	Sign:     "ZhFL5PsGfyPzPdnSEO3u+r0v1/3yrLBtQMErAd0IwJz9vY4+rTZfNhzfbxLhbg3l7NRRd9EMHtxsy0quXJNPBw==",
}

// Windows_5_0_0_alpha234_1559301070 is Windows 5.0.0-alpha234, build 1559301070.
var Windows_5_0_0_alpha234_1559301070 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha234 [Build: 1559301070]",
	Sign:     "X5SKQ8c8YGQvu4FC3E9pDzTBQAiz2SBwj7Z/woedk7feGBrj7hx3woASaEtQ33pVO0KseWVWbt8plUDFT2TuAg==",
}

// MacOS_5_0_0_alpha234_1559301070 is macOS 5.0.0-alpha234, build 1559301070.
var MacOS_5_0_0_alpha234_1559301070 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha234 [Build: 1559301070]",
	Sign:     "gMbSOGIYOP1PpHz0Aqt+xefZSytby56+8Z/IE4yg7Fo73b9LMb/qfQRO7VvlzwSB8c72/Sw4OyzPgB56+pmdDg==",
}

// Windows_3_3_0_1559307127 is Windows 3.3.0, build 1559307127.
var Windows_3_3_0_1559307127 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1559307127]",
	Sign:     "His8U9cnGKfL1f93iCm/9H5TSmtRFBBkcPW2czbcY7bA71IvQrXB+nxx7dNqilVxPZxqfB7yuKieGdA6kO+FBA==",
}

// Linux_3_3_0_1559307127 is Linux 3.3.0, build 1559307127.
var Linux_3_3_0_1559307127 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.0 [Build: 1559307127]",
	Sign:     "u9pIc5sk0+s1KqVj1Jrwl1eEu+1QUXOPTtPA9Q1Smt9Ym5N9mi6BOrV6Ke3DE6uu/7H0hBSYh2aeZLThX+LPDg==",
}

// OSX_3_3_0_1559307127 is OS X 3.3.0, build 1559307127.
var OSX_3_3_0_1559307127 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559307127]",
	Sign:     "uGMlFevcA6rER2uq1xdapqzmLreisA98yi/6LWK6GR2TyVWjXwMQ05DXAjflz/N4JUbuIal16BsEF/ByZ35LBw==",
}

// Windows_3_3_0_1559395482 is Windows 3.3.0, build 1559395482.
var Windows_3_3_0_1559395482 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1559395482]",
	Sign:     "npVq0Vd6BWXh3bhUNDAzAFU2iuQ/KIClddTjTk9QnBnF5l0uW9g1VkyjqBcDyLYpZEsa1ZFWVKOKlgnEjJJqCw==",
}

// OSX_3_3_0_1559395482 is OS X 3.3.0, build 1559395482.
var OSX_3_3_0_1559395482 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559395482]",
	Sign:     "RC8j63bAAQydHNNlBBJWhUS0NgMvMFhjgn6MNlzC4zQaoD61OuYrrrMyx6ks4gLwZ/+RWLBkXMZK4p+cZT6LBw==",
}

// Windows_3_3_0_1559423503 is Windows 3.3.0, build 1559423503.
var Windows_3_3_0_1559423503 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1559423503]",
	Sign:     "ULqbAwG4lV8TBYWv/W8hRfkwlXFURxuhlnM8AQYWJsPEIoJyeSQjMxqAU1rHySTqYPMRM+Q/dHHY5uD2nFJwCw==",
}

// Linux_3_3_0_1559423503 is Linux 3.3.0, build 1559423503.
var Linux_3_3_0_1559423503 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.0 [Build: 1559423503]",
	Sign:     "NZ173oDGAENOy9GIYGpnWPg4Em69GM8UX5C1jzxglbECIWzIcH5r4fVnuDbTZJiOgmBacgsg1y2RbYk5r3LrCA==",
}

// OSX_3_3_0_1559423503 is OS X 3.3.0, build 1559423503.
var OSX_3_3_0_1559423503 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559423503]",
	Sign:     "O/Q031RHvRZiYRwor/T6Wru50I9bX+pcFEpiYN6WF+jh8vti2IVkkTqoKHzYu/W6K7QN0JKcmOahoL2xARdUDw==",
}

// MacOS_5_0_0_alpha235_1559482103 is macOS 5.0.0-alpha235, build 1559482103.
var MacOS_5_0_0_alpha235_1559482103 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha235 [Build: 1559482103]",
	Sign:     "eYJ/ihasd7Szx2o6ECEY2m0e6GYfGIDDRVDzaIFqq5TJvqQuBFtuFx5eaEfddBRfBAmPhC+14DTYvW21IKvvAg==",
}

// Windows_5_0_0_alpha236_1559578284 is Windows 5.0.0-alpha236, build 1559578284.
var Windows_5_0_0_alpha236_1559578284 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha236 [Build: 1559578284]",
	Sign:     "QBAaSF/mQotdakJI/1KemvF2juB96IpvEqCe5fVlnSM3Jx0UV9jLnTkdYlBUYyLpRkB+DWO6GN48FnB27zNqAQ==",
}

// Windows_5_0_0_alpha238_1559732615 is Windows 5.0.0-alpha238, build 1559732615.
var Windows_5_0_0_alpha238_1559732615 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha238 [Build: 1559732615]",
	Sign:     "EusUrcu92SYBZj+5MjjuduCIyKYhFgEaKc70EQokZAxeeMsqATBYIzkggF1ji8DEUCbfohSiO+KMbLXUdtTtCg==",
}

// MacOS_5_0_0_alpha238_1559732615 is macOS 5.0.0-alpha238, build 1559732615.
var MacOS_5_0_0_alpha238_1559732615 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha238 [Build: 1559732615]",
	Sign:     "0lQWZ052Se6L/o2FZk0+kLzbDS6o3acKPSCMhISh/0CZZ7ETcF/6xjVVBGZuWPNPIL+/00ncu/AwibfSUM+HDg==",
}

// OSX_3_3_0_1559767425 is OS X 3.3.0, build 1559767425.
var OSX_3_3_0_1559767425 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559767425]",
	Sign:     "a8BpIJkdXEgxUOrFZ7Uk/fxLxOTGNdcyf4mPDC6BmXpdxjcLM5ps6U45o2tnfrd5xSONtPhaMLLLD1MhiZ2bDA==",
}

// Windows_5_0_0_alpha239_1559815502 is Windows 5.0.0-alpha239, build 1559815502.
var Windows_5_0_0_alpha239_1559815502 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha239 [Build: 1559815502]",
	Sign:     "91txA9V5csVkRKKs4+pDDhQO5Yh4Ca0Eh/EcNAbk9yJSUVF35XfXZFTH6SNr9xE3QpfHYgHG67YPM0TsuA6WBw==",
}

// Windows_3_3_0_1559832098 is Windows 3.3.0, build 1559832098.
var Windows_3_3_0_1559832098 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1559832098]",
	Sign:     "/klG/RS8bvimBdtvjJySVY7J6W810VoT/naLsi8t1aLTxA1UA9Q8n8Ze4rbMYXWKUqTpgP2dRlqnlPnV6uYDAw==",
}

// OSX_3_3_0_1559832098 is OS X 3.3.0, build 1559832098.
var OSX_3_3_0_1559832098 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559832098]",
	Sign:     "H3LyDEcQz3Rcz2CGd1Y1PqhgdUzAcO/5uoKZaeJ3qAuAc4DrChbsduBqHCb70cygPDcHT7iqM0zAeZAt9RFwAQ==",
}

// Android_3_3_0_1559834030 is Android 3.3.0, build 1559834030.
var Android_3_3_0_1559834030 = ClientVersion{
	Platform: "Android",
	Version:  "3.3.0 [Build: 1559834030]",
	Sign:     "Ux59iejFFnEANHPjL4dmwUgXKhvnV7dPqjzAIqYMNs0RoF9RyhsgxEaJO72IgNt7D3yaD+4lGtYfcEFG8WDKCg==",
}

// Windows_5_0_0_alpha241_1559838513 is Windows 5.0.0-alpha241, build 1559838513.
var Windows_5_0_0_alpha241_1559838513 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha241 [Build: 1559838513]",
	Sign:     "AouFlEmYwG+IhVSQN1IAN5mOLQnEos3XnTkCyBoPfyvxn0EQ8kCg9L6aHj6x4kd+KMGe1h/94oYk4vS3M1gjDQ==",
}

// MacOS_5_0_0_alpha241_1559838513 is macOS 5.0.0-alpha241, build 1559838513.
var MacOS_5_0_0_alpha241_1559838513 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha241 [Build: 1559838513]",
	Sign:     "DJytwJVmYEhdcEJHPOo7sg+oTVUFK5zRk3wRJn++OBNenKCoU7uSp1+GZbjU3nIDqrdBj9CL72dnjbCJDeVsBQ==",
}

// Windows_3_3_0_1559847347 is Windows 3.3.0, build 1559847347.
var Windows_3_3_0_1559847347 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1559847347]",
	Sign:     "gffOfzgmsY79PAQ4Hk2zHU7fpYgOsQU42Li7GnuGzORdmxmw5EpS1+sA/RYe7RsMdzkNxhvPQ3QhM2jDxJjQDw==",
}

// Linux_3_3_0_1559847347 is Linux 3.3.0, build 1559847347.
var Linux_3_3_0_1559847347 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.0 [Build: 1559847347]",
	Sign:     "eu5V4pF+XgYBg4ig2/C8NEpAjBncsoeHJXDyHAXziZktezDNYTsJIIW6BkFLg4N/TiIdIJif54pCEM4L7oeODA==",
}

// OSX_3_3_0_1559847347 is OS X 3.3.0, build 1559847347.
var OSX_3_3_0_1559847347 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1559847347]",
	Sign:     "Aft/7c6PYAmhwJctkpgPWbDgV4fkeN3vt0MHNEligntg7xQBSyNECO38ghO0dl25Su6A/vHBXxxobn6YAr5wBw==",
}

// Windows_3_3_0_1560032346 is Windows 3.3.0, build 1560032346.
var Windows_3_3_0_1560032346 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1560032346]",
	Sign:     "9IPmbngc2CpvGe9inLOFpoJCxoU86yObNUJ1fLTzuPJCh54j4zFidNnv3Xe59gKgMzDHZ5/7H65Hubsi8j9+Cg==",
}

// Linux_3_3_0_1560032346 is Linux 3.3.0, build 1560032346.
var Linux_3_3_0_1560032346 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.0 [Build: 1560032346]",
	Sign:     "X8sXjPPNm42tCNhFrfNhWb4OiZMlkx2HXaLOAOJilEiG+Vs77BR//AxUuB+iZa8crBOWLgrE66oh2u4q2QcuBQ==",
}

// OSX_3_3_0_1560032346 is OS X 3.3.0, build 1560032346.
var OSX_3_3_0_1560032346 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1560032346]",
	Sign:     "2iOqRuzxYSJeB+7MB20alBy61Nm9E/UlqgvbRxtN7MYTLhy0kuaAXjQYpI6HImWM/X6UJjckZvAUBg0aK7zbBQ==",
}

// Windows_5_0_0_alpha242_1560169692 is Windows 5.0.0-alpha242, build 1560169692.
var Windows_5_0_0_alpha242_1560169692 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha242 [Build: 1560169692]",
	Sign:     "Q42kSe5LxJ1/sNqojdxgBwTsXMXvTmz9Ipk8eQptq6AiwOj0qS2UqapIU8Wlir0zvWYN4675mT/e/ce6yn8pAA==",
}

// MacOS_5_0_0_alpha242_1560169692 is macOS 5.0.0-alpha242, build 1560169692.
var MacOS_5_0_0_alpha242_1560169692 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha242 [Build: 1560169692]",
	Sign:     "9AbGQKw34QuJg2gRcfzp0JkIdmyVWrRAUn0BOKVscQGo98CoiAEKJixVhQxsoDBb4YpgPhdTeBkGMuJy9BRVCQ==",
}

// Windows_3_3_0_1560189475 is Windows 3.3.0, build 1560189475.
var Windows_3_3_0_1560189475 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1560189475]",
	Sign:     "glcuW51nfgvusH5yBKRGvSfRRGD7I+5hWEXmK1spfOQoPVLMe46u/oxKJeIKMietJ7bLAG1t18dCI3CysuBFBQ==",
}

// OSX_3_3_0_1560189475 is OS X 3.3.0, build 1560189475.
var OSX_3_3_0_1560189475 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1560189475]",
	Sign:     "WhDvkhicz+E4w/g8NRfDIRWOb8vEJkHIJjW8IiGLzx7R0o51mN7AJ9GaSVfH4za4+TGdKGFrs8Sl2VUlreqFDQ==",
}

// Windows_3_3_0_1560265364 is Windows 3.3.0, build 1560265364.
var Windows_3_3_0_1560265364 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1560265364]",
	Sign:     "3dnvBngFvSg1elIctIK8j/TWfdaxaoaf+4W3dc2v1QBW8AhTx+2zlxOaGBDFXYfL6asP82krFgoPXeEtVFVkDw==",
}

// OSX_3_3_0_1560265364 is OS X 3.3.0, build 1560265364.
var OSX_3_3_0_1560265364 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1560265364]",
	Sign:     "Qscrve6CfWXAshiOjvUSmshhHV8QKx1FsrUmkzaOmRAFrg+SZYvjLBQsdV+xSb4UyI0v77iyXQDv82Q4/l6eAg==",
}

// Windows_5_0_0_alpha243_1560345924 is Windows 5.0.0-alpha243, build 1560345924.
var Windows_5_0_0_alpha243_1560345924 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha243 [Build: 1560345924]",
	Sign:     "ijnSy4j+gfMrSheNHP1NLhGr9J+k/jvpIaxnkmI7iwDMNg1Gqn/SIjpDqWvcdztETrDlwJ4doYYwjteGubnxAQ==",
}

// MacOS_5_0_0_alpha243_1560345924 is macOS 5.0.0-alpha243, build 1560345924.
var MacOS_5_0_0_alpha243_1560345924 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha243 [Build: 1560345924]",
	Sign:     "L8dmXQrk3+gxHpIHr6sTxr3ujyGI68oCtuOLYLDSfv/6YkEzxGJPp6pcO774ptrllOj7Td8RzTsNSaEQZo7PDw==",
}

// Windows_3_3_0_1560464251 is Windows 3.3.0, build 1560464251.
var Windows_3_3_0_1560464251 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1560464251]",
	Sign:     "bkUu9ipgPnyMDOCbJG9rPTB87JWx4ZpCk3tKGut6dXnXgenYROA+BvPzN1k147kJ4Jdyh504E+2E7laxb8eFAQ==",
}

// OSX_3_3_0_1560504952 is OS X 3.3.0, build 1560504952.
var OSX_3_3_0_1560504952 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1560504952]",
	Sign:     "5lk5x+337M2JI/TRCD9/zZoUBBqLiKjf3KdLvqyt2dTk0VCA+aG0LWgZszJR0D7lbhtA4ez4OY3GjyoOa1+uAA==",
}

// OSX_3_3_0_1560546557 is OS X 3.3.0, build 1560546557.
var OSX_3_3_0_1560546557 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1560546557]",
	Sign:     "FY4pOaQF7XKxVIgIIuMJOhka9b7Fb/VLtSiHRkOstOItA8alGsR8BAD6rKVAJnBuGFv5uG3RcxHF3yydBriECA==",
}

// Windows_3_3_0_1560850141 is Windows 3.3.0, build 1560850141.
var Windows_3_3_0_1560850141 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.0 [Build: 1560850141]",
	Sign:     "v9gCHwBYJKBxLWwptMvqhj+tvWuSAz/AjcThvv/J3ZNsPeivRk4P9Y9YtalQbIRkrALQSC+qNc5wIAw4HG2cCA==",
}

// Linux_3_3_0_1560850141 is Linux 3.3.0, build 1560850141.
var Linux_3_3_0_1560850141 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.0 [Build: 1560850141]",
	Sign:     "8giDUlJFDtdmzpfyngDzL3UP47C1+U1iwrzROU70MoiSeswf1oJujYeQ1bx4dD2OPxF4Avi/XgbZUQ/Y4NcDAA==",
}

// OSX_3_3_0_1560850141 is OS X 3.3.0, build 1560850141.
var OSX_3_3_0_1560850141 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.0 [Build: 1560850141]",
	Sign:     "Z/UJgrYae1BsdKJfvMorW4/zIQ8E0sKBMTBI5Cm58oYE3TtCE9+1FpUE9VkqWSm3J8SMmu2+J/FpaK6pa8KaBQ==",
}

// Windows_5_0_0_alpha247_1561047486 is Windows 5.0.0-alpha247, build 1561047486.
var Windows_5_0_0_alpha247_1561047486 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha247 [Build: 1561047486]",
	Sign:     "7RDCJ1DN4Q+bh9FQlDdkYK5OURj/H8kwrPcxKCUXB67Al0ouj41vNzOCYul+c2hNNrv4wdmxjHjYN74T6dDVDA==",
}

// MacOS_5_0_0_alpha247_1561047486 is macOS 5.0.0-alpha247, build 1561047486.
var MacOS_5_0_0_alpha247_1561047486 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha247 [Build: 1561047486]",
	Sign:     "9i+SzqDeOjSdwfQEhD/hC6arCpCaorBbELfKSVqx4CifMIv+xOtBkWPhOqg5ISTKkqUPeMBvgberODEgilMbDQ==",
}

// MacOS_5_0_0_alpha248_1561153809 is macOS 5.0.0-alpha248, build 1561153809.
var MacOS_5_0_0_alpha248_1561153809 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha248 [Build: 1561153809]",
	Sign:     "YNHobK/oj9XzKKo2A/qcckWvHfhu0X+WeOu1rvfHHAS6S2ri8839R7GiVvN3+w01ZfxBWI5z3590Cqb3cC2qCA==",
}

// Windows_3_3_1_1561236585 is Windows 3.3.1, build 1561236585.
var Windows_3_3_1_1561236585 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.1 [Build: 1561236585]",
	Sign:     "IV1j5Xoh3qck4Vlr3KqNuo9FYxKJ1BhVTNJ1vf2AvCQPEnQP6cYb9L4bBE4fsCw/+OiyQXt6IWm7G2cuVeC0Dg==",
}

// Linux_3_3_1_1561236585 is Linux 3.3.1, build 1561236585.
var Linux_3_3_1_1561236585 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.1 [Build: 1561236585]",
	Sign:     "2WaGpMt2Ky110SIh+byPcwkS+Dn9U2l7VffcJsoq2PNy0ZQ+o+N2i9wR4/7kEgtgB4SHIdoA7W8rQW2LLqUaAA==",
}

// OSX_3_3_1_1561236585 is OS X 3.3.1, build 1561236585.
var OSX_3_3_1_1561236585 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1561236585]",
	Sign:     "sSQDnOTwkEeo1shjPUwbs5w/xU9+5641b4695H5uGjL956turKroMABAyco7Xu4FEO6NWV0MWQDmzN5CUNEYAQ==",
}

// Windows_5_0_0_alpha249_1561367386 is Windows 5.0.0-alpha249, build 1561367386.
var Windows_5_0_0_alpha249_1561367386 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha249 [Build: 1561367386]",
	Sign:     "jgzbESSPVFNW6ZS5SG8XhSLqN6uJb5ZHFM7Hvt0JeqLSBusvLap8VEyEO0BPAFeEQV+yCs0VB8U8ny8LzSnKAw==",
}

// MacOS_5_0_0_alpha249_1561367386 is macOS 5.0.0-alpha249, build 1561367386.
var MacOS_5_0_0_alpha249_1561367386 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha249 [Build: 1561367386]",
	Sign:     "MKOmBOjtv+ikyJ8NuYfr82CJCPcr1f5vBa55XTMzsV7YsN75hiLxTIHY0VOeAlI0MPnW8Mrdf5tDZHqCayiYAA==",
}

// OSX_3_3_1_1561495949 is OS X 3.3.1, build 1561495949.
var OSX_3_3_1_1561495949 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1561495949]",
	Sign:     "zCiWyOrsK8oVYT9iiLacxAB6x51Cf9jVIivvbh3gcagSudLFB/U+ZxqFZHCYxDklqTS6dBvjHaTc1OrFQxFBCg==",
}

// MacOS_5_0_0_alpha252_1561656532 is macOS 5.0.0-alpha252, build 1561656532.
var MacOS_5_0_0_alpha252_1561656532 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha252 [Build: 1561656532]",
	Sign:     "1bujQHTuZ1AdYDamCS5VkEnjSEeAztO2Y8UeP4ZlN1MFrBh7dTkIN2DoGTI1/Lk+oXYua0NHgnik06UtkgICCg==",
}

// MacOS_5_0_0_alpha253_1561732636 is macOS 5.0.0-alpha253, build 1561732636.
var MacOS_5_0_0_alpha253_1561732636 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha253 [Build: 1561732636]",
	Sign:     "sTvuj4X+PHD38NdHVkvLprzM/fcU4J12A0AMlYRxSXuPzDjVfLTThQoSwK8Ih3AZL6xIoegehhHolaZXawlbCg==",
}

// Windows_3_3_1_1561761890 is Windows 3.3.1, build 1561761890.
var Windows_3_3_1_1561761890 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.1 [Build: 1561761890]",
	Sign:     "oGoGqFyELQKn/ZWpZl0r+oFJVpByp8d7C5ZPiaf6QjvG73uUrNvZUCUTaqTGf0QkLdktXD0HNULPqlxCfrf1Dw==",
}

// OSX_3_3_1_1561761890 is OS X 3.3.1, build 1561761890.
var OSX_3_3_1_1561761890 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1561761890]",
	Sign:     "whf5UirES/hy/MeQmtraD7++MwLemejC79wXb2D3hwMQQH7kS6ieUOpkVnt/9PJxn6wVg2HeONo2uT1Kt9MaBw==",
}

// Windows_5_0_0_alpha254_1561967684 is Windows 5.0.0-alpha254, build 1561967684.
var Windows_5_0_0_alpha254_1561967684 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha254 [Build: 1561967684]",
	Sign:     "jT69rm0NjtyA6BuZ83zcm6AD64qCgU+ipF5qI8g1XAGyejLIBS/WLCOmqCUFZTPJgBXXxpzWyBmC3kHOxJVCAw==",
}

// Windows_3_3_1_1562186016 is Windows 3.3.1, build 1562186016.
var Windows_3_3_1_1562186016 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.1 [Build: 1562186016]",
	Sign:     "3U+9nlyiUqF4rcAOhKoJgaSaRW8TQzwiSfkEXq3MH/Gr/f9ur/khYN8P4+kPHPopA5l5IYU21G95Ift1hCrnBg==",
}

// Linux_3_3_1_1562186016 is Linux 3.3.1, build 1562186016.
var Linux_3_3_1_1562186016 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.1 [Build: 1562186016]",
	Sign:     "EyCld6pZjXiiDEXmA8iJmq0BHyiXknORkKJ+9ySuhbtQGUf0VOsfYYJ+dNjhNNwlmYmsd2ZD6rJ2oeaG7Mi5Aw==",
}

// OSX_3_3_1_1562186016 is OS X 3.3.1, build 1562186016.
var OSX_3_3_1_1562186016 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1562186016]",
	Sign:     "l+cJl+SdNwU8e2B3lKL6s8NCsBDhgQ0sXOM0qq6AnsCFkERxznGaLY51vgg2NQBINtqAOueA5LNec+bZXyFMCw==",
}

// Windows_5_0_0_alpha257_1562592572 is Windows 5.0.0-alpha257, build 1562592572.
var Windows_5_0_0_alpha257_1562592572 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha257 [Build: 1562592572]",
	Sign:     "zmnSfIV0k+PRN8Qhd+2DMZQo9PuZraAx6ERAyMVyqu7UnXiIKrlMDUNSr1Ul3EPz4BzX82QSwB3tyeZYHZ1nBg==",
}

// Windows_5_0_0_alpha258_1562611926 is Windows 5.0.0-alpha258, build 1562611926.
var Windows_5_0_0_alpha258_1562611926 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha258 [Build: 1562611926]",
	Sign:     "ae4LAzyzPBlPcWFQEoiYsuheWOCvW1HnqXMEM+Y6Aed9tsCewzYglA5YkBlbXe9HM1kf3c/huGy63qJrrJrcAg==",
}

// Windows_5_0_0_alpha259_1562680101 is Windows 5.0.0-alpha259, build 1562680101.
var Windows_5_0_0_alpha259_1562680101 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha259 [Build: 1562680101]",
	Sign:     "rJJ6ECPqdvCw/4pFYAlKoHJ1yzmz0CskKfP/E9dG936W9efpnIt6ZHB5EywlDTksA8gTHanxl6zqNgQ4bnbuCg==",
}

// Windows_5_0_0_alpha260_1562686022 is Windows 5.0.0-alpha260, build 1562686022.
var Windows_5_0_0_alpha260_1562686022 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha260 [Build: 1562686022]",
	Sign:     "Cq3SKxNkD3w7TbTCp/4dN2Pm7POHie5wTugASXsqhQBImLwvH5PpxxpuBGAHCYCP5tYswKHL/9grzeZFK/Q/BQ==",
}

// Windows_5_0_0_alpha261_1562743548 is Windows 5.0.0-alpha261, build 1562743548.
var Windows_5_0_0_alpha261_1562743548 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha261 [Build: 1562743548]",
	Sign:     "xGhA35RYhl7Dnb/ruDpLSD3hQHEcD5f6sZOdGgHMQ8w1/DqBHDg+JPFc2pPapN8mS3sk6R1j+YXLCMFNpM22Bw==",
}

// Windows_5_0_0_alpha262_1562749547 is Windows 5.0.0-alpha262, build 1562749547.
var Windows_5_0_0_alpha262_1562749547 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha262 [Build: 1562749547]",
	Sign:     "4qye7Z9lHZFEEdn9kGRhthAPbekPZ/kiwlZ0n8HR/Qojz28dkk9jtJGBXi6SoeSMisGa1eRe+K1f5plpdNqxCQ==",
}

// Windows_5_0_0_alpha263_1562771414 is Windows 5.0.0-alpha263, build 1562771414.
var Windows_5_0_0_alpha263_1562771414 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha263 [Build: 1562771414]",
	Sign:     "owzBAJ05B/Zj4aLNC34famFSFtrg2oA2NROFfJkstXWKA6c8tCuWxa2e8lUqO+5FluF8SrCG09k7hjOwWQcSBg==",
}

// Windows_5_0_0_alpha264_1562775539 is Windows 5.0.0-alpha264, build 1562775539.
var Windows_5_0_0_alpha264_1562775539 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha264 [Build: 1562775539]",
	Sign:     "Ta3PfkIvQHU+zyx18Yk2y0e5pSfUZ/7sERryRyJTgwQIs/FbmTxwqX9RVzIlnPtkWevF+A1U0kv/FzHIZvX6AA==",
}

// Windows_5_0_0_alpha265_1562849836 is Windows 5.0.0-alpha265, build 1562849836.
var Windows_5_0_0_alpha265_1562849836 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha265 [Build: 1562849836]",
	Sign:     "RIDPBmjBeYRpq6ZUhKG8FdEjIw2ikTMmvr0jFTMXpth34KXOAdX+iBRCH4arRDUmwCRmjqx0eprrgt7LYFihDg==",
}

// Linux_5_0_0_alpha265_1562849836 is Linux 5.0.0-alpha265, build 1562849836.
var Linux_5_0_0_alpha265_1562849836 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-alpha265 [Build: 1562849836]",
	Sign:     "t+XvNBHJr2bfK88LTXeixtr/dClF3vGFwLSiCdARkcWABykx09uzczpFRtCJWR8eYQ3ov5KXQFxce8/oeI9TDQ==",
}

// Windows_5_0_0_alpha266_1562943568 is Windows 5.0.0-alpha266, build 1562943568.
var Windows_5_0_0_alpha266_1562943568 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha266 [Build: 1562943568]",
	Sign:     "cOTquwaHmv9Gcv+ubFzSMS3xFR9UN7r9YXJWmdoIv3QfIetEDlpntTbklLxpRPLIUSmEkdCBQ0iDhpLB9ql3AA==",
}

// OSX_3_3_1_1563026407 is OS X 3.3.1, build 1563026407.
var OSX_3_3_1_1563026407 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1563026407]",
	Sign:     "jmdDSzzwrzb/qtgd+AAqnCzZSpVng/lfmVYXEt9avpbNE0w5+MNgvkAqBGmtD9PNHfiGFC6tfmIaVTElW402DQ==",
}

// OSX_3_3_1_1563049771 is OS X 3.3.1, build 1563049771.
var OSX_3_3_1_1563049771 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1563049771]",
	Sign:     "jUO4qwNRZBeBm+UV7+ft0hvxDHyvS4jRpB6Tk75UNJbHz9DYOTfix0kbPB/c35IV3yJpbKnYoyQaaRQxKD7SAA==",
}

// Windows_5_0_0_alpha_267_1563202431 is Windows 5.0.0-alpha-267, build 1563202431.
var Windows_5_0_0_alpha_267_1563202431 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha-267 [Build: 1563202431]",
	Sign:     "W26q3qQ7Ntn+1cqXQGR3J1j8u46qMj+ADEwuTfT1F80DENcCYe9VmbODAGd8wPDkY1it7B24VYMMSUWJzy5yBQ==",
}

// Windows_5_0_0_alpha268_1563300665 is Windows 5.0.0-alpha268, build 1563300665.
var Windows_5_0_0_alpha268_1563300665 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha268 [Build: 1563300665]",
	Sign:     "FJN1araOIDI8eFoiY502BwABOv/Me8VF9khBb3tFaBH/L34c2fzTspIKVwZFs88AlXjGuZNHaatEhJN/LG5kDQ==",
}

// MacOS_5_0_0_alpha268_1563300665 is macOS 5.0.0-alpha268, build 1563300665.
var MacOS_5_0_0_alpha268_1563300665 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha268 [Build: 1563300665]",
	Sign:     "D1DlyZVevsgVnp0lVoc3LjLsWTjo3g7AJJV3J0bCl+yW5rvKfLsz/JIdrak2MtuSbQdJ/1yXLKONbcBABfz7AA==",
}

// Windows_5_0_0_alpha269_1563374719 is Windows 5.0.0-alpha269, build 1563374719.
var Windows_5_0_0_alpha269_1563374719 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha269 [Build: 1563374719]",
	Sign:     "LWPHabA4y5rnzvl54YmRS9d4reoQVV6m2xraGfGnhdDAeKwdlwRfAPBoypSM1GUQf0170CYNW+U8ylrhtZoODA==",
}

// Windows_5_0_0_alpha275_1563647591 is Windows 5.0.0-alpha275, build 1563647591.
var Windows_5_0_0_alpha275_1563647591 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha275 [Build: 1563647591]",
	Sign:     "DR2+Qid9DhlZViTHp6aEbc9yHmqUK4Dj+ktgZW1O9zBaSozIx1+n4InG+41GlQ5bAU/W1+bLhhw+Jfm8YTL5BA==",
}

// Windows_5_0_0_max_updater_test_3_1563793735 is Windows 5.0.0-max-updater-test-3, build 1563793735.
var Windows_5_0_0_max_updater_test_3_1563793735 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-max-updater-test-3 [Build: 1563793735]",
	Sign:     "7BgxUIi/tZgE/rfJSkrn7LDoFxDAS1x1gJ+LT53/dzO6olR5njakmCLORQthMv/GOdFhoSl5rl5mfajzAmtdCQ==",
}

// Windows_5_0_0_alpha279_1563868868 is Windows 5.0.0-alpha279, build 1563868868.
var Windows_5_0_0_alpha279_1563868868 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha279 [Build: 1563868868]",
	Sign:     "KinjpNU0pUxwJc9qoaksQgXQBhaT57NsL8ofj+/qN7GRTxuRP6gyCWUf9vw7XU/dzouyDFC16NZ+Mj6jKF5zAg==",
}

// MacOS_5_0_0_alpha282_1563983977 is macOS 5.0.0-alpha282, build 1563983977.
var MacOS_5_0_0_alpha282_1563983977 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha282 [Build: 1563983977]",
	Sign:     "UdsQQGhtR5gFl12iQg+nLQyoBgyCPIIezEk54x0zWxfYA4B0hvEFyn4N+7oVKBXa56Rl/71zQsvdgyPnrPV/DQ==",
}

// Windows_5_0_0_alpha283_1563988444 is Windows 5.0.0-alpha283, build 1563988444.
var Windows_5_0_0_alpha283_1563988444 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha283 [Build: 1563988444]",
	Sign:     "i+rGXZwXJBEm8SrP9BlU1udbNbZrST3ZliJSwZ+rf+GpQN8kU2Tpmr2vw6IqpYmwidi/lIyn17LHaWxS8GpADg==",
}

// MacOS_5_0_0_alpha283_1563988444 is macOS 5.0.0-alpha283, build 1563988444.
var MacOS_5_0_0_alpha283_1563988444 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha283 [Build: 1563988444]",
	Sign:     "4UcLBuEHOsP7KPXrH5PoJWJwkd59XBcBvicsIKyqVdO1TJ1BOBgDkGD+/Qy0WM8UXx7Bjn19WRk9/0EHGxK9Dw==",
}

// OSX_3_3_1_1563999377 is OS X 3.3.1, build 1563999377.
var OSX_3_3_1_1563999377 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1563999377]",
	Sign:     "6H3kBrosheF+ce6+bzJFnBeoMZ+qKXQVASW/xvSXqwL2IQDOC+2KZj9PvaDLqvZRLkXs5EHCKu9RTgSiTrXXCw==",
}

// Windows_3_3_1_1564146308 is Windows 3.3.1, build 1564146308.
var Windows_3_3_1_1564146308 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.1 [Build: 1564146308]",
	Sign:     "2AzTbQOY/RXgTIISnT3vS25Wow1FBr3CLCU7f0hDFEO9FbFfFu2VB7GAmkd0twJkNKyG2T8uCjMmBeHibt5tBQ==",
}

// OSX_3_3_1_1564146308 is OS X 3.3.1, build 1564146308.
var OSX_3_3_1_1564146308 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1564146308]",
	Sign:     "zQYCeNs6rkDp/383oOB39toCbKwl6KgfPJps4v/3duXSbVpotOar6sb+4QgrlubK9T+ypuwExnNIZyaf/ScnCA==",
}

// Windows_5_0_0_alex_scroll_test_1_1564164327 is Windows 5.0.0-alex-scroll-test-1, build 1564164327.
var Windows_5_0_0_alex_scroll_test_1_1564164327 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alex-scroll-test-1 [Build: 1564164327]",
	Sign:     "K9aAi7XNPXDPF+rmgIUHOcDNXfTq/liLQWFZY90/1CxfH/IY/HK7UwQo5Xiny6ZKZnvhxU4oM2gTtqyhjaCVBg==",
}

// OSX_3_3_1_1564391039 is OS X 3.3.1, build 1564391039.
var OSX_3_3_1_1564391039 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1564391039]",
	Sign:     "k0iL0DU3iIOnL0ZHyIPtOo6Cg7ESCzrSDoLflFjO9/hrn4PvFBtb5gsTpj4Q6Ua15AEFYeemL2tqyeyzU5AxAA==",
}

// Windows_5_0_0_alpha291_1564408069 is Windows 5.0.0-alpha291, build 1564408069.
var Windows_5_0_0_alpha291_1564408069 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha291 [Build: 1564408069]",
	Sign:     "IGd5L2DM5Pn4EKhWmxB4onfII0UgZ2gE6mFX0KSoQi2DENuVE0ymnaj7dSd01wabiyYkSiuDyUrqqIgKNOkIDQ==",
}

// MacOS_5_0_0_alpha291_1564408069 is macOS 5.0.0-alpha291, build 1564408069.
var MacOS_5_0_0_alpha291_1564408069 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha291 [Build: 1564408069]",
	Sign:     "JhaFJdvPijlh6tu9olWfJgB2Ps/FaG+bZPMDCBWE7uC3Citd+p9uyMrw7qefaEvKotJqRzMq7LsU5vgmrPSmCw==",
}

// Windows_5_0_0_alpha292_1564497029 is Windows 5.0.0-alpha292, build 1564497029.
var Windows_5_0_0_alpha292_1564497029 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha292 [Build: 1564497029]",
	Sign:     "jlFBHcHdjFMn3nYnFUK3CgL3uxtb2BQQ4Dsc+gqIYOMrUPzS0CsMD6kuQJFUOF7aIKQ8y9euFKtuv9G57fdyCQ==",
}

// MacOS_5_0_0_alpha292_1564497029 is macOS 5.0.0-alpha292, build 1564497029.
var MacOS_5_0_0_alpha292_1564497029 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha292 [Build: 1564497029]",
	Sign:     "PNWDdpHthSNKYCd8w3yCljxM8QBbdVN5f4hC04p6LZrS9oCQXwaNFirbRd+qUxwdF/ZaCGz9W8IQUvQiqOodCQ==",
}

// Windows_5_0_0_alpha293_1564586764 is Windows 5.0.0-alpha293, build 1564586764.
var Windows_5_0_0_alpha293_1564586764 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha293 [Build: 1564586764]",
	Sign:     "ZT9k6ShVBg3ZF/koi55DJttu1vcI8AmZcULRfN8YhGQa9fEkS9qIpj3gP6HKq7fh9dESvoKksRORq59RiH8xBQ==",
}

// Windows_5_0_0_alpha295_1564653261 is Windows 5.0.0-alpha295, build 1564653261.
var Windows_5_0_0_alpha295_1564653261 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha295 [Build: 1564653261]",
	Sign:     "BFrjFCQZRX/dPiHhIqOYj7oUZ9TXeNUdZEengJgfEvTboZ9t4ztVG4DWX6wORiior1Xc7e3+BtUxWq/FronKAw==",
}

// Android_3_3_1_1564671328 is Android 3.3.1, build 1564671328.
var Android_3_3_1_1564671328 = ClientVersion{
	Platform: "Android",
	Version:  "3.3.1 [Build: 1564671328]",
	Sign:     "0IDm4WX5vzyGfNrXHxd/TU6t5AC+AuWx3KF8Bh3n5R+adbrroIi/uHqg0WV8xxWThupRDp0UlqyH2STRuu50DA==",
}

// Android_3_3_1_1564678999 is Android 3.3.1, build 1564678999.
var Android_3_3_1_1564678999 = ClientVersion{
	Platform: "Android",
	Version:  "3.3.1 [Build: 1564678999]",
	Sign:     "kPqHuXEgLxpThXc5XYdvTLk+iaY0AL99jf2WJIXKBJuCJmD0pfW1Ep/zYCxU2NGsu4HIHMMXnB0d2lkr7AHiDw==",
}

// OSX_3_3_1_1564695891 is OS X 3.3.1, build 1564695891.
var OSX_3_3_1_1564695891 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1564695891]",
	Sign:     "U8tvJN1f5SnXikUJLzobwuWqA1N3eS+1GRFcVnztpJOwBOFT//wee6I1WSAoAUHFshK7HSrWnGJUBnXT1Sd9Aw==",
}

// Windows_5_0_0_alpha300_1564750918 is Windows 5.0.0-alpha300, build 1564750918.
var Windows_5_0_0_alpha300_1564750918 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha300 [Build: 1564750918]",
	Sign:     "1dtJaIlnJj8SMM4fdL9APze8nljwAYtEPNFiUT5J3v5E2h1pW8aJnnljBCWSYcFGgKL3Jrj5okC/Ix7gR86cBA==",
}

// MacOS_5_0_0_alpha300_1564750918 is macOS 5.0.0-alpha300, build 1564750918.
var MacOS_5_0_0_alpha300_1564750918 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha300 [Build: 1564750918]",
	Sign:     "xc3aQ7iiWOI3VZb4gHBg9OhQcTxqSu4HgdIBj9N58JhrYz2ioXkSZaNmjRoTjmlIrcPSHawMMozKkjQ4cfY7CA==",
}

// Windows_5_0_0_alpha302_1565122993 is Windows 5.0.0-alpha302, build 1565122993.
var Windows_5_0_0_alpha302_1565122993 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha302 [Build: 1565122993]",
	Sign:     "0pF71saHDtwBs+WntxBBjIdZhSyNBpsth8qiqDBlKCf54et7bN8zvhlUFuySO2nQQQTaC6Nbn+H1PeY2ERvuCw==",
}

// Windows_5_0_0_alpha304_1565173045 is Windows 5.0.0-alpha304, build 1565173045.
var Windows_5_0_0_alpha304_1565173045 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha304 [Build: 1565173045]",
	Sign:     "ArizbxJu/9+vi4QrBLWeCneB4e7+do6z4PAcGymxNGtL/aLQPqmAkhpCGs++YWndtZp6HrysrKAYwP0vB04EAg==",
}

// MacOS_5_0_0_alpha306_1565180063 is macOS 5.0.0-alpha306, build 1565180063.
var MacOS_5_0_0_alpha306_1565180063 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha306 [Build: 1565180063]",
	Sign:     "vRWUMMtf0bOSVNxCOlXrvw/e6YLHCzcLqocEb3SkSmG7OtXrMSzV+qp7UyhM40YdYi0zQblZjCMo9cVJDBKyAw==",
}

// Windows_5_0_0_alpha308_1565255370 is Windows 5.0.0-alpha308, build 1565255370.
var Windows_5_0_0_alpha308_1565255370 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha308 [Build: 1565255370]",
	Sign:     "reS/VSqXlHry/XR+hg3j8nSp25o5gmuJnlKM0IbC/FW/ufVNo68qhVOgtqYY+8VZbf4f3Lf40CKh3MxPwyYuBQ==",
}

// OSX_3_3_1_1565359284 is OS X 3.3.1, build 1565359284.
var OSX_3_3_1_1565359284 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1565359284]",
	Sign:     "X2zQPJvqLMIHhFOqg2VK20pz3th5+x3MRYNq9fSu4YeH2RQ2yuiVA+gutHOGfaHJfHXddGi9pHbmfqsG13tiAw==",
}

// Windows_5_0_0_alpha312_1565621064 is Windows 5.0.0-alpha312, build 1565621064.
var Windows_5_0_0_alpha312_1565621064 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha312 [Build: 1565621064]",
	Sign:     "oF7DxSVLcG/rzTMH10g10mc0yg+MRY0TICPdBoU3zOmMwDm/9+gZWsvL8if3ifCSCAmkSQ34lB7rb/3Sah22CQ==",
}

// Windows_5_0_0_alpha313_1565694680 is Windows 5.0.0-alpha313, build 1565694680.
var Windows_5_0_0_alpha313_1565694680 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha313 [Build: 1565694680]",
	Sign:     "+OscPH6RxOtkhFOBunnFBI8QsoVLZOLuLfTMf4CZpJRdwwlly3QbUL9Prx/M0yaYpPozJ4vKMajyWxlXAmJ0CA==",
}

// Windows_5_0_0_alpha314_1565805211 is Windows 5.0.0-alpha314, build 1565805211.
var Windows_5_0_0_alpha314_1565805211 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha314 [Build: 1565805211]",
	Sign:     "cWjRa7Z0tIYKF7HUQ6Z52Xgm6P0GnD9vn8yi1Tt9HZYgREohgPIssdpqDCkPx7Kwi9hxfBnp9sjnJ/Z/ZzC7CQ==",
}

// Windows_3_5_0_1565805756 is Windows 3.5.0, build 1565805756.
var Windows_3_5_0_1565805756 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1565805756]",
	Sign:     "0SzCC2IGgn+ovlPoZUAeyxxSsuqQjyJkK1m2be+PfjniFU6F37cw/KpX1rBrllnaMrv2DFiG54ub1IHF5j/GCg==",
}

// Windows_5_0_0_alpha316_1565975113 is Windows 5.0.0-alpha316, build 1565975113.
var Windows_5_0_0_alpha316_1565975113 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha316 [Build: 1565975113]",
	Sign:     "7jKMe5MDxTa+5KZ3luvBCJPG/xkh8t7bx8PitvtnNTVedQmpZUECONFtP/ceM1+Flq5x8OCkXT8tnF9E7dz7DA==",
}

// Windows_5_0_0_alpha317_1566233926 is Windows 5.0.0-alpha317, build 1566233926.
var Windows_5_0_0_alpha317_1566233926 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha317 [Build: 1566233926]",
	Sign:     "bOlLrOlFsFwvXk4YEjcF4xZoB/T7MTpsHlOqzNYBGeY1dvk5ShiHobmDVUSjNVoHkvyYC6Jti3FlJdTIq5viBA==",
}

// OSX_3_5_0_1566479450 is OS X 3.5.0, build 1566479450.
var OSX_3_5_0_1566479450 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1566479450]",
	Sign:     "Mqkms76I9VfgFUELEursGojag6/2ZFrELtGs/VwmDFxLVFJ134pfsobaCGljdOPJc61wUA39A//hqXuN/ZQRCg==",
}

// Windows_5_0_0_alpha319_1566479610 is Windows 5.0.0-alpha319, build 1566479610.
var Windows_5_0_0_alpha319_1566479610 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha319 [Build: 1566479610]",
	Sign:     "W9DQ53AWolbst7XISRwIZHzOYfm/Y/Dmxi/wD6oUIM63SCjLBuGYpUoLlLIdkWe2bTRZxfysv8CMiiAhoFCpBA==",
}

// MacOS_5_0_0_alpha319_1566479610 is macOS 5.0.0-alpha319, build 1566479610.
var MacOS_5_0_0_alpha319_1566479610 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha319 [Build: 1566479610]",
	Sign:     "ESvw+cfkAgZRjlh7X3GRMhqZq1N+w5iTm3dQbFIbIFuBFwWgoyYk9RQVo9ZjjkEBT92Xm5gSp2/dCK6pNZp+DA==",
}

// Windows_3_3_1_1566673023 is Windows 3.3.1, build 1566673023.
var Windows_3_3_1_1566673023 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.1 [Build: 1566673023]",
	Sign:     "utZjz6KhPiaR9zdhS3NvbLpi4oTGH/vseHd9/mUrLxYYD5JvfeeHH6nzLf8H3manoNrQnONsCcqUOvYglCotCQ==",
}

// Linux_3_3_1_1566673023 is Linux 3.3.1, build 1566673023.
var Linux_3_3_1_1566673023 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.1 [Build: 1566673023]",
	Sign:     "IdO00q19oqEwf9CB1R2c+2ZALMrUC6YPwTohdmD9abnDzpfDH/P/p70oDolrL+pRLoh1LjDiLtUdKRETLbeqAw==",
}

// OSX_3_3_1_1566673023 is OS X 3.3.1, build 1566673023.
var OSX_3_3_1_1566673023 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.1 [Build: 1566673023]",
	Sign:     "dNpW3zyuLCNdhCJpCbaCHWob9xnHSbrRNyJgNShwAPQfyclrtarPLOiTYN9IgQbIGxTu1Yo4fra59VHzpHhaDQ==",
}

// Windows_3_3_2_1566767614 is Windows 3.3.2, build 1566767614.
var Windows_3_3_2_1566767614 = ClientVersion{
	Platform: "Windows",
	Version:  "3.3.2 [Build: 1566767614]",
	Sign:     "fAjM3pPl95eGXrhFcsvCXgdI6Epr8XpafOJZlYbFws2VMllYy/4DUleSVzPuVqu/TCgrTaqb0wP+KANse3/vAw==",
}

// Linux_3_3_2_1566767614 is Linux 3.3.2, build 1566767614.
var Linux_3_3_2_1566767614 = ClientVersion{
	Platform: "Linux",
	Version:  "3.3.2 [Build: 1566767614]",
	Sign:     "UhiFNnz8npgT22qkLXlZJnX3T2n+a8usv/0cTh+tgybrgsFd2WIuI3eabWCibPeU+AYeHLaeYR+x+pF4GX/NDw==",
}

// OSX_3_3_2_1566767614 is OS X 3.3.2, build 1566767614.
var OSX_3_3_2_1566767614 = ClientVersion{
	Platform: "OS X",
	Version:  "3.3.2 [Build: 1566767614]",
	Sign:     "JiKoykMS5BExaAEMpIYB3JRH+YturPua/Q+VTQxJGRi002zni9b8ReitLaJJQt2EMcNAbDpl57um4mekqFvGBA==",
}

// Windows_3_5_0_1566810730 is Windows 3.5.0, build 1566810730.
var Windows_3_5_0_1566810730 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1566810730]",
	Sign:     "KJlE8//AeT9nmBTs0EIjEZT7+W2Qc/J76Tevu+QlnP8jqG+079SUeJ9jZkl+L9I0MwBTyrCSkpUoDGv6MH3CAg==",
}

// Windows_5_0_0_alpha324_1566898458 is Windows 5.0.0-alpha324, build 1566898458.
var Windows_5_0_0_alpha324_1566898458 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha324 [Build: 1566898458]",
	Sign:     "cfTebCrUaA/YvCMbLPXC2Q94+9Hs1RssCo2w8zyw9psLJ6x6A8JGiYBAB1VFiRdh0Roc83q3ghAYr7ia1ay1Bw==",
}

// Windows_3_5_0_1566914096 is Windows 3.5.0, build 1566914096.
var Windows_3_5_0_1566914096 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1566914096]",
	Sign:     "dRC2UOZSRcleMujmFMWtN33/AqfFuZeM8M1bxPckUnLWugC91nv2DqFC9ohTKCzlCy6fE5Pnm+FUF2ZpYip8Dg==",
}

// OSX_3_5_0_1566914096 is OS X 3.5.0, build 1566914096.
var OSX_3_5_0_1566914096 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1566914096]",
	Sign:     "JiMiehYrCDP2x8U49KEBRtBtD7QgCxqJ6ALhs1Mt/IOtSluOuR2XhuCBUOoTRe20WfgDfHhlUk/AbAdKgdmyAA==",
}

// Windows_5_0_0_alpha325_1567003912 is Windows 5.0.0-alpha325, build 1567003912.
var Windows_5_0_0_alpha325_1567003912 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha325 [Build: 1567003912]",
	Sign:     "Gt1OMdHeKcWpo8A6sfuMM4MwZITOgy8xJo2t263rsLRq35pbtgr6UtjsAeMqxlIZRGKnJsG2l9qGZkYihwBMBQ==",
}

// Windows_5_0_0_alpha327_1567025817 is Windows 5.0.0-alpha327, build 1567025817.
var Windows_5_0_0_alpha327_1567025817 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha327 [Build: 1567025817]",
	Sign:     "VYcfgvRKy7btgTQgxpfSYRupK8dAAmlayqa3bs3x7gWrwZXLQH11OSRY4HBOx6Bs3AMMGdooTs1FXpFWbpMrAg==",
}

// Windows_5_0_0_alpha329_1567160967 is Windows 5.0.0-alpha329, build 1567160967.
var Windows_5_0_0_alpha329_1567160967 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha329 [Build: 1567160967]",
	Sign:     "VLAHSsiIyvBC+Xr9NWSjR29chi/aJ76IRG4lLUZoec93cr0KFraQOFIZZUJqF4wASq0wB/Xb6cWdiCS+XUrOBQ==",
}

// Windows_5_0_0_cef_77_test_9_1567209083 is Windows 5.0.0-cef-77-test-9, build 1567209083.
var Windows_5_0_0_cef_77_test_9_1567209083 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cef-77-test-9 [Build: 1567209083]",
	Sign:     "QlubfeDQgkhhd6vk5zvqg81BdItyEp04TbS0hj8WHxab/lwBy9ell8EuTyU65+xMDdliGb8jmyi3UZEJ7Ee2Dw==",
}

// Windows_5_0_0_alpha330_1567246409 is Windows 5.0.0-alpha330, build 1567246409.
var Windows_5_0_0_alpha330_1567246409 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha330 [Build: 1567246409]",
	Sign:     "ZdPf2YHlMX9moxzE82/zKZQ2QPqThxPa08f8rLzgYCrtLafjQcY1LjIfev0tB2hKGKzPd9aRX2UhCWRaPAGvAQ==",
}

// Windows_5_0_0_alpha332_1567435866 is Windows 5.0.0-alpha332, build 1567435866.
var Windows_5_0_0_alpha332_1567435866 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha332 [Build: 1567435866]",
	Sign:     "KOKtxZUj/qQ6GAh6HyRtkLipFrfptUa72zl548InSwGziz3s+METYqEX6ghqlxtmjPjopdKeozY0kdBCp8VjAQ==",
}

// Windows_5_0_0_alpha333_1567450575 is Windows 5.0.0-alpha333, build 1567450575.
var Windows_5_0_0_alpha333_1567450575 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha333 [Build: 1567450575]",
	Sign:     "92XoD+2CniLMhP+aopIUMQWGrbrFtdX+CaNja4ZKs4CSAg6JuiPtKX9JHldnl03IXPUT5exxBbEojsWkuOd8DA==",
}

// Windows_5_0_0_alpha334_1567590370 is Windows 5.0.0-alpha334, build 1567590370.
var Windows_5_0_0_alpha334_1567590370 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha334 [Build: 1567590370]",
	Sign:     "+F0kmE8CmGE7gz7r3VaW2Qb2HmVyXCNwMO7LVdHJN+4dlYNu6taoWfa78HivqXUZH4s+zOfjweol3tyJ3x5UCw==",
}

// Windows_5_0_0_alpha335_1567603533 is Windows 5.0.0-alpha335, build 1567603533.
var Windows_5_0_0_alpha335_1567603533 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha335 [Build: 1567603533]",
	Sign:     "iifdsQpgwFyiN1LpUq4oCvA2oMPTfhO19Ic367PJDxoJBErlM3COoW/LJyaR+/AyfoEPYVPzK/HVsgm2VH94Aw==",
}

// Windows_5_0_0_alpha336_1567680535 is Windows 5.0.0-alpha336, build 1567680535.
var Windows_5_0_0_alpha336_1567680535 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha336 [Build: 1567680535]",
	Sign:     "t/bEfvxvDT2TZkLmU42Q0Mf+yXcOqizJ8G15RNOO6UgTjSnTjh64bJAwAayko6IMN/xZpIDgx9m/9hMhGcPICA==",
}

// Windows_3_5_0_1567687511 is Windows 3.5.0, build 1567687511.
var Windows_3_5_0_1567687511 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1567687511]",
	Sign:     "c6+vv7Rp1fQsFxkKlYfy4kaF8/5Xh4I+ZwHw+hqV4qPo8AsPc5ZTwcWtK6Q9/6WKs3i2msq6p47mg6sBHSa6AA==",
}

// Windows_5_0_0_alpha337_1567692133 is Windows 5.0.0-alpha337, build 1567692133.
var Windows_5_0_0_alpha337_1567692133 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha337 [Build: 1567692133]",
	Sign:     "vFDmsTT6gI1njnCOJv3mLt9EIJERoBubpEiadmZLBaXdXmbsqC655Ywq1Zsnt9/5axOLobOt5/C6ZHJfuWOVDA==",
}

// Windows_5_0_0_alpha338_1567761846 is Windows 5.0.0-alpha338, build 1567761846.
var Windows_5_0_0_alpha338_1567761846 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha338 [Build: 1567761846]",
	Sign:     "I3ifOYOw5lNb8+vHLgbFQl0/SGNSw+1w7E0mCT/Zh5GHYbbrpxQDR0a9SdUHi7TKQ55uxTAt0Sc68fhQBEABDg==",
}

// Windows_3_5_0_1567775523 is Windows 3.5.0, build 1567775523.
var Windows_3_5_0_1567775523 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1567775523]",
	Sign:     "496shsf4bckjKJsMYlJW1p82rWxuL08+GMZP9S171X/2rXeuXWpQ3AfkI7tMve95MiZ5/GNt6Vl6jn0/45h9Aw==",
}

// OSX_3_5_0_1567775523 is OS X 3.5.0, build 1567775523.
var OSX_3_5_0_1567775523 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1567775523]",
	Sign:     "d5asvnlZOJucbg1E3A2JUJ2IrxJ0Q4pJlrMwvZhsvxTK5D2dW4TUJIcQmDnndgC4FKrk//VMHsnrtFIfhhrCCQ==",
}

// Windows_5_0_0_alpha339_1567776032 is Windows 5.0.0-alpha339, build 1567776032.
var Windows_5_0_0_alpha339_1567776032 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha339 [Build: 1567776032]",
	Sign:     "1FwZpwSPVZQiwCkhSlzl4ki+cmhTc0C7LbzPSQTNKqFXPv/UMld0dw+05nCSng3UHVu+2MmuXUxfokIIA3GJDg==",
}

// Windows_5_0_0_alpha340_1568047589 is Windows 5.0.0-alpha340, build 1568047589.
var Windows_5_0_0_alpha340_1568047589 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha340 [Build: 1568047589]",
	Sign:     "pNAG0mkBI8izK+bEW1bh5gEkaSo4ih6YAVsU89f+XsdXH4SvUq3PvWQy5aSuUSHAIgSChfIzFNbNa8Q5cmTFBQ==",
}

// Windows_5_0_0_alpha341_1568138230 is Windows 5.0.0-alpha341, build 1568138230.
var Windows_5_0_0_alpha341_1568138230 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha341 [Build: 1568138230]",
	Sign:     "foVufjNlvsZPOejfZEUgAi8ENTHOsijOF+qAULN29FoUpWFKNgBFeDYOuy1Hf0pVkv8y9ariYjh0OWhcY5OnCQ==",
}

// MacOS_5_0_0_alpha341_1568138230 is macOS 5.0.0-alpha341, build 1568138230.
var MacOS_5_0_0_alpha341_1568138230 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha341 [Build: 1568138230]",
	Sign:     "K1sdP0hCrN8CVI6urHRI9GBCbKg0GiaVfxt/WQR/x9qTzUj2Q2sFbJL3DEh/dadOY3gI4TAGUji2mFiERYfUAw==",
}

// Windows_5_0_0_alpha342_1568216929 is Windows 5.0.0-alpha342, build 1568216929.
var Windows_5_0_0_alpha342_1568216929 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha342 [Build: 1568216929]",
	Sign:     "Vd6t8B66K91JwqEAKqitP6gobwsIQg7Wtg5ffH6CBGN2TWKg7BGCDJabCUHjnUI7hm6eCtWBqr0lFv9GTHxACg==",
}

// Windows_5_0_0_alpha343_1568303604 is Windows 5.0.0-alpha343, build 1568303604.
var Windows_5_0_0_alpha343_1568303604 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha343 [Build: 1568303604]",
	Sign:     "MuWpPz3L+MIN7HAwbI+IeA5fUcHjzyIsGlQ/QrajpoWEkhfk4Fl9yB/q9BWJwDxDiRyT//KpRzPmYVK5ps7jBQ==",
}

// Windows_5_0_0_alpha345_1568462524 is Windows 5.0.0-alpha345, build 1568462524.
var Windows_5_0_0_alpha345_1568462524 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha345 [Build: 1568462524]",
	Sign:     "hFUXangYNdyo7ENnEJ7Czi6JFRBRMreoB6cqWCWesvfoasY5VR6Wkvy5JyziqT9EHO7E7V+f53e/BpeV2wQFDg==",
}

// Windows_3_5_0_1568483207 is Windows 3.5.0, build 1568483207.
var Windows_3_5_0_1568483207 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1568483207]",
	Sign:     "P+9QNU8aPVwf1Hk2oiZUUckRg1989KnGXj6FB2AV1GxGoeaGb0e1PYhhP5E3eTIjFDr0W0k9ELrcoo1+i0/IAw==",
}

// Windows_5_0_0_alpha347_1568498600 is Windows 5.0.0-alpha347, build 1568498600.
var Windows_5_0_0_alpha347_1568498600 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha347 [Build: 1568498600]",
	Sign:     "p19wMaSxX8UXuvhlDlxIc/KrSdfJ9+o8wAXOtMRcprxu9z3nvcmpmCWMUIIOYQg64hyr7nms6hrGkIYH98CxBw==",
}

// Windows_5_0_0_alpha348_1568542448 is Windows 5.0.0-alpha348, build 1568542448.
var Windows_5_0_0_alpha348_1568542448 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha348 [Build: 1568542448]",
	Sign:     "P53ztJ8EKNZT2cxr7InF0xFicDlGGHXyM8BOcxWv/kqm3VLVxLQCVE60XVY+ar1SzZ2KZ7ZD1Rt6NyI42wR5Cg==",
}

// MacOS_5_0_0_alpha349_1568550521 is macOS 5.0.0-alpha349, build 1568550521.
var MacOS_5_0_0_alpha349_1568550521 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha349 [Build: 1568550521]",
	Sign:     "/risCZ6WJqff77LQA3hZqIMaL0XfeC/haaErc6bY7fuGwacTbtc80G6ZEGfFpnJ1NUscfHALAujH8VxDavWgBQ==",
}

// Windows_3_5_0_1568734736 is Windows 3.5.0, build 1568734736.
var Windows_3_5_0_1568734736 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1568734736]",
	Sign:     "fyTB0CPBTj0jVd4NTUy8oBJ1PiGhrHpano2wGvEmzzZxb8A0A1BkRdmCyZP2hxJI8iLMnpEIy3SEXADl8kjRAg==",
}

// Linux_3_5_0_1568734736 is Linux 3.5.0, build 1568734736.
var Linux_3_5_0_1568734736 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1568734736]",
	Sign:     "YU9jsFPaBFg9CEr4g2lUBhZj6e6f2l7EFI9grYLMB/BLPWu9B7k+aGzAe9OkMHXpT3Q0cqc+k+N7XSxXf8x0Dw==",
}

// OSX_3_5_0_1568734736 is OS X 3.5.0, build 1568734736.
var OSX_3_5_0_1568734736 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1568734736]",
	Sign:     "cD1hdW/GpYEHd42RTeKVVqTPbMlcGNNYLbsrjE3bX3NNyBEw+EFDn6JiXjvJ2nlgkwt/BG1CqTjeTPxCWhg4Cw==",
}

// Windows_5_0_0_alpha352_1568742967 is Windows 5.0.0-alpha352, build 1568742967.
var Windows_5_0_0_alpha352_1568742967 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha352 [Build: 1568742967]",
	Sign:     "rVdkwzZbfhuqxr8XrVT07NmI7KWh9yuKukRAeeVnA6TSiZlnDzVpKsFeZ+XRvQqlg9f6NQjM6mOGJFd4Z/TwBw==",
}

// MacOS_5_0_0_alpha353_1568828473 is macOS 5.0.0-alpha353, build 1568828473.
var MacOS_5_0_0_alpha353_1568828473 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha353 [Build: 1568828473]",
	Sign:     "F+3xGce0D7mujDxL179YtEhO61SY6iqu5Fa2bKhWRY9C/cUGGSXDNKrn4A1fe5M8NkJDH2HsnuNCSQHssQnlCw==",
}

// Windows_5_0_0_alpha354_1568887729 is Windows 5.0.0-alpha354, build 1568887729.
var Windows_5_0_0_alpha354_1568887729 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha354 [Build: 1568887729]",
	Sign:     "Uh8IYEDWqgJWvm0n3CW6wLZwxNtL2wQWxuePrBJhkLGWT8GFjB1DjPRHknHoDSBUgae+TDzkle57owFienMLDg==",
}

// Windows_5_0_0_alpha355_1569001691 is Windows 5.0.0-alpha355, build 1569001691.
var Windows_5_0_0_alpha355_1569001691 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha355 [Build: 1569001691]",
	Sign:     "2HjF3/5YQt6TXdHAv4g1wXlt5fm3ffpmW42MERDz0lWaAEfgE0VsfwAAHXmiBl6Sgjt8ExN0kjGlNtUg3p4AAg==",
}

// Windows_5_0_0_alpha356_1569007610 is Windows 5.0.0-alpha356, build 1569007610.
var Windows_5_0_0_alpha356_1569007610 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha356 [Build: 1569007610]",
	Sign:     "KDYbc9yRky+5ene8ASeIA8xawtKV+2FatCqvNOb13kVM1xNTmgC6atTmXbfGYxppEnmBwl23wfcieQlZgblNAw==",
}

// Windows_5_0_0_alpha357_1569014091 is Windows 5.0.0-alpha357, build 1569014091.
var Windows_5_0_0_alpha357_1569014091 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha357 [Build: 1569014091]",
	Sign:     "Olo878lO79Q+Rgs+yh4Y1b8rbo9+GOBXg2ydwU8tVVkJNh6HTDSGKdx7BP5cko8eca2cXCyjlwVIvDjvvrmLBg==",
}

// MacOS_5_0_0_alpha357_1569014091 is macOS 5.0.0-alpha357, build 1569014091.
var MacOS_5_0_0_alpha357_1569014091 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha357 [Build: 1569014091]",
	Sign:     "ArZMgswMs1SK06P3JwW/LpDfEeeG9bnbxSI6QJPDIFgckqXrFZ/tkDFsH2ZO8/VqS/CnlUvEqEtqITjlOajAAw==",
}

// Windows_5_0_0_alpha362_1569439429 is Windows 5.0.0-alpha362, build 1569439429.
var Windows_5_0_0_alpha362_1569439429 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha362 [Build: 1569439429]",
	Sign:     "oiMZEu9yAdpPcbQiHC5QX2JLkndvZS+yjJp46DQnuG/7iYgwP5JlDHjyP393FQZSQMNClXwJ17jBXXGAtpOXDw==",
}

// Windows_5_0_0_alpha366_1569577640 is Windows 5.0.0-alpha366, build 1569577640.
var Windows_5_0_0_alpha366_1569577640 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha366 [Build: 1569577640]",
	Sign:     "b50/TxvYKGnC+1+rKRPnJ1PCfKNIbsvAXdPeTcjn8BEYk3eYOT9TTMJ/Qg93H2sJJYWm01bb1SCqG546/uX8Cg==",
}

// Windows_5_0_0_alpha369_1569852696 is Windows 5.0.0-alpha369, build 1569852696.
var Windows_5_0_0_alpha369_1569852696 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha369 [Build: 1569852696]",
	Sign:     "IhRZBIxx+luuBhNtQAjfrAXS6plahEzfX4Jvxd6+c6WnnSlIvFC4z5CZ8aLyTis+1s/BlO/4vMs3RewsShHlAw==",
}

// Linux_5_0_0_alpha369_1569852696 is Linux 5.0.0-alpha369, build 1569852696.
var Linux_5_0_0_alpha369_1569852696 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-alpha369 [Build: 1569852696]",
	Sign:     "9EOn5V3u/349Q3dZtbouoo2UwQn6Oq1AOvXj4jBcZjgoLoDq8UfofVgYNOxs814RMEc60SsBOcvxYJAS8yciBg==",
}

// MacOS_5_0_0_alpha369_1569852696 is macOS 5.0.0-alpha369, build 1569852696.
var MacOS_5_0_0_alpha369_1569852696 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha369 [Build: 1569852696]",
	Sign:     "AE+kHmgA+aHt7i23Q3+ghDBcHJUX26MgVoBcuMjexFcghUhvHI9ooRcR6S6LNPjfqfuPxLU9SOrC6beImJMDCw==",
}

// Windows_5_0_0_alpha370_1569948695 is Windows 5.0.0-alpha370, build 1569948695.
var Windows_5_0_0_alpha370_1569948695 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha370 [Build: 1569948695]",
	Sign:     "hRgqeJvTICIg/tR9/7zjb7uu6nSaGR2ypyvj52sOXp0N1wq8WdZgvs80dlC/+eLnmWDWkFIpbq/AgBYNaleWBw==",
}

// Linux_5_0_0_alpha370_1569948695 is Linux 5.0.0-alpha370, build 1569948695.
var Linux_5_0_0_alpha370_1569948695 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-alpha370 [Build: 1569948695]",
	Sign:     "JwzqAbSxXDTD9VLF4BZhOFYu2etYzwqg3TmN/50WSejPvs0Dkb66wu6llyhRBVTE/GB5o/vQxlsFjrP2rM3ADQ==",
}

// MacOS_5_0_0_alpha370_1569948695 is macOS 5.0.0-alpha370, build 1569948695.
var MacOS_5_0_0_alpha370_1569948695 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha370 [Build: 1569948695]",
	Sign:     "3Nu8NJNG4Jx5WTaZkuja1UMm5x1zPQjH/MMAwvhXcEDPLgPjFVMCW8vqrQU5GeiCehB9sYdq+IdAFYNfieEFDQ==",
}

// MacOS_5_0_0_alpha373_1570024161 is macOS 5.0.0-alpha373, build 1570024161.
var MacOS_5_0_0_alpha373_1570024161 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha373 [Build: 1570024161]",
	Sign:     "d6q4l+SJBwfp3WmDSRdr1CSPH3DwBFwLQUQQnRne7UgbhacrmbCAleroUBqSPKUay9QdPaECatzRu5GM4o6fDA==",
}

// Windows_5_0_0_alpha376_1570136727 is Windows 5.0.0-alpha376, build 1570136727.
var Windows_5_0_0_alpha376_1570136727 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha376 [Build: 1570136727]",
	Sign:     "VMsCdtH4U0FpPSQ61J3hGt/tYL3Ys3N3x9lgOUiS3nlYdltNZ5PBfvL4Q64VpTImK2rj/8u6JKKTdXdgDuZsAQ==",
}

// Windows_5_0_0_alpha377_1570211017 is Windows 5.0.0-alpha377, build 1570211017.
var Windows_5_0_0_alpha377_1570211017 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha377 [Build: 1570211017]",
	Sign:     "UExsYhgJK3YjzwIZhm2ztveSGNpruZ7rpP0kS/d1lNTsIezasOw3uoiYq5Tj1GIyZMrVV+dZNzyCnsjtdpfDAA==",
}

// MacOS_5_0_0_alpha377_1570211017 is macOS 5.0.0-alpha377, build 1570211017.
var MacOS_5_0_0_alpha377_1570211017 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha377 [Build: 1570211017]",
	Sign:     "UPuXS+zY1OBoib5DYjuvgoeaFShhm8s9k38pkMY9AvHm8dy6AghFFkUT1YLdMO/n1ej4TUo8/lP5BuhRYl21Dg==",
}

// Windows_5_0_0_alpha379_1570306886 is Windows 5.0.0-alpha379, build 1570306886.
var Windows_5_0_0_alpha379_1570306886 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha379 [Build: 1570306886]",
	Sign:     "lmAAKNKEjYw1MVqPiQpTP+fgHkZBr4YI7PVk92XUPweb+/qAHqrIAGGjRSaDqEfrYnWhtXMnJ8O+wGyZ9DIlAg==",
}

// MacOS_5_0_0_alpha379_1570306886 is macOS 5.0.0-alpha379, build 1570306886.
var MacOS_5_0_0_alpha379_1570306886 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha379 [Build: 1570306886]",
	Sign:     "hsSZSM2saFnDrRcrJdBGhqPNDC1EGopIoFnjKXe7K9bwtyEt2gTZ7uRasA46YQX2sTSKHCBDiaXj07WVH5ooCQ==",
}

// MacOS_5_0_0_alpha380_1570376142 is macOS 5.0.0-alpha380, build 1570376142.
var MacOS_5_0_0_alpha380_1570376142 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha380 [Build: 1570376142]",
	Sign:     "5aM0m+9G1SWQmfYiRzNNBTjUg5wlULAq5aVVQbVvL/LseEGRLafgTChu4K7Vn5avJK5dVbEyP852EGrGveK3Bg==",
}

// Windows_5_0_0_alpha381_1570394174 is Windows 5.0.0-alpha381, build 1570394174.
var Windows_5_0_0_alpha381_1570394174 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha381 [Build: 1570394174]",
	Sign:     "kIadWcCh+5r216TvDS4+FVpvG1xWSVjJAcaKbKecdJS2isBlUogVLn/xcvq89GRrg4kZgIMuf4YCPFx6vPFgDg==",
}

// Windows_5_0_0_alpha_383_1570427845 is Windows 5.0.0-alpha.383, build 1570427845.
var Windows_5_0_0_alpha_383_1570427845 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.383 [Build: 1570427845]",
	Sign:     "ZicJJDvBhYeB9CNIzUUPr5vQeJ2PQ4MZsrUqzrk+cwl8qO8hVyVoUa5BD+dqE+8I35/Kjh4k/VraNCgxQQEyCg==",
}

// Windows_5_0_0_alpha_384_1570457406 is Windows 5.0.0-alpha.384, build 1570457406.
var Windows_5_0_0_alpha_384_1570457406 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.384 [Build: 1570457406]",
	Sign:     "6FmjeQaMhIELrglADHocwtXPH8XWODz5UOJDwa3wDDuVMX/K9Vnyh6+MrSR9UT+TuGBnVXtSYGpNeKL7i9LNCA==",
}

// Windows_5_0_0_alpha_385_1570480817 is Windows 5.0.0-alpha.385, build 1570480817.
var Windows_5_0_0_alpha_385_1570480817 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.385 [Build: 1570480817]",
	Sign:     "RFB5R9JktLjj/ttr65Aq++U6gR56H3uccY2P6RoioahY1YT6UFr9rym+7tX4g6CjnQjXxhkYekewFr2Luqn7CA==",
}

// Linux_5_0_0_alpha_385_1570480817 is Linux 5.0.0-alpha.385, build 1570480817.
var Linux_5_0_0_alpha_385_1570480817 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-alpha.385 [Build: 1570480817]",
	Sign:     "8+c1g72+1sHXfYz5SHYO9ylwbOkoY0IthOd2Kl7Kuj4jR87mf9ATLqsKlZCfZ1nIbLs6do42CDhxLldyKgisDA==",
}

// MacOS_5_0_0_alpha_385_1570480817 is macOS 5.0.0-alpha.385, build 1570480817.
var MacOS_5_0_0_alpha_385_1570480817 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha.385 [Build: 1570480817]",
	Sign:     "tgmX8pvk2XSvVlmTNlSF7zteBfSdG+vQujanrpg73B6TZVpIMW52aC8E/p2X+jvYm09DNm8MVeUOPglfGtadCA==",
}

// Windows_5_0_0_alpha_389_1570642878 is Windows 5.0.0-alpha.389, build 1570642878.
var Windows_5_0_0_alpha_389_1570642878 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.389 [Build: 1570642878]",
	Sign:     "WkxMeVeRlBaZkz1WVicXimyHKf7xBjWxOaFG1QmkMsob4ohzvz6qUZqwZ3QZKH61okE+T37rvl31mxZVtP6jBg==",
}

// MacOS_5_0_0_alpha_389_1570642878 is macOS 5.0.0-alpha.389, build 1570642878.
var MacOS_5_0_0_alpha_389_1570642878 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha.389 [Build: 1570642878]",
	Sign:     "jQxZ7U0XmElM1Mg3UEtU+16RIZM9svvghZ1Pgluca0scXBbkA1v1x9tb94pDOvBS5UyANrFEUTv31PbMXAV3DQ==",
}

// Windows_5_0_0_alpha_390_1570728651 is Windows 5.0.0-alpha.390, build 1570728651.
var Windows_5_0_0_alpha_390_1570728651 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.390 [Build: 1570728651]",
	Sign:     "UBZr57UKwatZBGZF8p8ZDtqy4dg/1lsnXyLgTrNLLvydRq6aOdFTsbzvZgcW8LwzojK2SKxM67VT5idB7VTIBQ==",
}

// IOS_3_5_0_1570810399 is iOS 3.5.0, build 1570810399.
var IOS_3_5_0_1570810399 = ClientVersion{
	Platform: "iOS",
	Version:  "3.5.0 [Build: 1570810399]",
	Sign:     "RdN1+nQ2YRxJi66Yd8ta7CXUMsisWTU64qGNDTyuV2vdO/+vYQz6qOUaWjwDxzw3JAXr8FfCPcPaPo3suJj7AA==",
}

// Windows_3_5_0_1570811287 is Windows 3.5.0, build 1570811287.
var Windows_3_5_0_1570811287 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1570811287]",
	Sign:     "9SgqZFHFIVXhObnqoJCEQuB0XHKVjFE+hrpEmOwj5f0xr5wTeznFeysUPP8g4cmhFHHyEzDt1EJu4ZCIEvZZBA==",
}

// OSX_3_5_0_1570811287 is OS X 3.5.0, build 1570811287.
var OSX_3_5_0_1570811287 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1570811287]",
	Sign:     "fNbZJmz470itRKI7lejb4jOMbnorqw2KlEgagkG/tFtxDyBxTlb1yb6VbJkik86ybDPiMvIRyEhlYF7Pg69GBA==",
}

// Windows_5_0_0_alpha_392_1570909746 is Windows 5.0.0-alpha.392, build 1570909746.
var Windows_5_0_0_alpha_392_1570909746 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.392 [Build: 1570909746]",
	Sign:     "NxrgnbjbCzhC9DI/MiwZTgXtm+9CzaqfANOGB8xcFQTPGZV1lk3hoDjdWOmr/7xF0Ulyx01eeQIgVxOALwHOBg==",
}

// Windows_5_0_0_alpha_393_1570924185 is Windows 5.0.0-alpha.393, build 1570924185.
var Windows_5_0_0_alpha_393_1570924185 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.393 [Build: 1570924185]",
	Sign:     "TlIOn5sV9djXtDcUrJX1CnhAELO9L92SUeWbKw9CCpL+BDcFVRerGOcUfSL9fG02/xszfwOHSYyhtimRbUBcBQ==",
}

// Windows_5_0_0_alpha_395_1570968752 is Windows 5.0.0-alpha.395, build 1570968752.
var Windows_5_0_0_alpha_395_1570968752 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha.395 [Build: 1570968752]",
	Sign:     "eJ4aaEhWHVMI+7SWH98ufmfhxw3PrZ10fo3e2e1Xn95tx99D6TwP35tuj1hdyN4SjSGAiNrWri9yptT1sOfxDA==",
}

// Windows_5_0_0_beta_1_1571050541 is Windows 5.0.0-beta.1, build 1571050541.
var Windows_5_0_0_beta_1_1571050541 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.1 [Build: 1571050541]",
	Sign:     "bIXuHNwfc/yJbpkrXYicrha6lmCC4jzXJuUSZjd14vMhmAsI66KW5n18Pg3TGFG7iKKhrpj0trc/4gpmDecBAw==",
}

// Linux_5_0_0_beta_1_1571050541 is Linux 5.0.0-beta.1, build 1571050541.
var Linux_5_0_0_beta_1_1571050541 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.1 [Build: 1571050541]",
	Sign:     "ojPTLLbwu5JAnFWX0To1uPa4dv2tX0CZ8a1kQIyvev+60jdiKxCY5ohN9VBvGaPenb/YJQinaZkjKbd4I/rfDw==",
}

// MacOS_5_0_0_beta_1_1571050541 is macOS 5.0.0-beta.1, build 1571050541.
var MacOS_5_0_0_beta_1_1571050541 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.1 [Build: 1571050541]",
	Sign:     "f7PTrjSUlknBxanjdmAMamgzYdGSY7LDRCDg8Hi7Miml0TnciOgn5wukGCeayjT7bpw/DeV3kwnSaoEDZ7PiBQ==",
}

// Windows_3_5_0_1571080050 is Windows 3.5.0, build 1571080050.
var Windows_3_5_0_1571080050 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1571080050]",
	Sign:     "4XIHXqnhLM6dRNFzdkNcbWxK/nX6iLBECc+6UJPX4PooBDyWOzul6yF1NKe/fg7bZDigZir1+OENu+O/tLwHDw==",
}

// Linux_3_5_0_1571080050 is Linux 3.5.0, build 1571080050.
var Linux_3_5_0_1571080050 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1571080050]",
	Sign:     "glUVQf9FU2STvK2jzW328FkF1AhrPLj27sVo9TzEC+2Qg7phv5UpczW9SGTyp3H0KCofYfmTR6OW/W/1tCoeBQ==",
}

// OSX_3_5_0_1571080050 is OS X 3.5.0, build 1571080050.
var OSX_3_5_0_1571080050 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1571080050]",
	Sign:     "64wKoleYoqOwO2t4bCHaQevSlv6HyvU5vpOF+yjuIrbqT1um1VoIQuL3L9BKt10Em2sd6VR1/IciCVuTSNd+BQ==",
}

// Windows_5_0_0_beta_2_1571087114 is Windows 5.0.0-beta.2, build 1571087114.
var Windows_5_0_0_beta_2_1571087114 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.2 [Build: 1571087114]",
	Sign:     "6zuLZzAe2WoM2BpYkEpG3u2zgsuzpWossd8O87wj+z+4+zeVTx7RvIZbW5Zzz3qZX46Rimz312PRcoXhQ+SLBg==",
}

// Linux_5_0_0_beta_2_1571087114 is Linux 5.0.0-beta.2, build 1571087114.
var Linux_5_0_0_beta_2_1571087114 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.2 [Build: 1571087114]",
	Sign:     "0ROgVlI/3lI0p5bm0sABq7zfG3U7E7qZLtOfPwf2RflkOygvVgKdlgEsKqpQT340tUcF6NuWZqiwoYXyyZnwAw==",
}

// MacOS_5_0_0_beta_2_1571087114 is macOS 5.0.0-beta.2, build 1571087114.
var MacOS_5_0_0_beta_2_1571087114 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.2 [Build: 1571087114]",
	Sign:     "0S6T2tVpyvoBfPlsM2S1GiF8ookfbqNtFV2ZS/c3EM51ncuVEtD6YrlYC5tGvBPlggbEXawRFQAmM/BwnAZMDg==",
}

// Windows_5_0_0_beta_3_1571155625 is Windows 5.0.0-beta.3, build 1571155625.
var Windows_5_0_0_beta_3_1571155625 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.3 [Build: 1571155625]",
	Sign:     "yd5c0kDs0E94yjZ6uP+LPtoU0gUXddjPoTLQ0ZJBYGgmtGNE92qlHN+OOINwoae0UNCJD90JVua7CJDeF/FlDg==",
}

// Windows_5_0_0_beta_3_1571214214 is Windows 5.0.0-beta.3, build 1571214214.
var Windows_5_0_0_beta_3_1571214214 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.3 [Build: 1571214214]",
	Sign:     "Gla9L+BRb4Y5Am8TbK0kvTTZ05G0HiACtO915NiP7rAD6Sd8+lXFsHK2REL+5akjvDBbHdU1BEwPBlu6RNaSAQ==",
}

// Linux_5_0_0_beta_3_1571214214 is Linux 5.0.0-beta.3, build 1571214214.
var Linux_5_0_0_beta_3_1571214214 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.3 [Build: 1571214214]",
	Sign:     "ymBfVBW72lTqkUUXWZmcahBs7nBG0hGEvAjEpp38iDQ+EIqI/VwVOPOgzVsFATumKCilmiIt33Pxj3+mePFLCA==",
}

// MacOS_5_0_0_beta_3_1571214214 is macOS 5.0.0-beta.3, build 1571214214.
var MacOS_5_0_0_beta_3_1571214214 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.3 [Build: 1571214214]",
	Sign:     "eLT0AWXP9u0tzMpJzJKLpjFx/9FyU8Wrrk1Zg4AKaPT1539RmbOqd7QxKV6r61PBWfE0U9y5GHRuivCi1P8YDg==",
}

// MacOS_5_0_0_beta_5_1571252771 is macOS 5.0.0-beta.5, build 1571252771.
var MacOS_5_0_0_beta_5_1571252771 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.5 [Build: 1571252771]",
	Sign:     "eySiC0JfF4VFxQPa3XO3eoM088PLWJqNCY7gdScCbdBy3nHiAb5qz07yXkmme9r3egVKl/8S2zyvo9dJDMPHAQ==",
}

// MacOS_5_0_0_beta_6_1571338027 is macOS 5.0.0-beta.6, build 1571338027.
var MacOS_5_0_0_beta_6_1571338027 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.6 [Build: 1571338027]",
	Sign:     "Mq+To2AHXyAAGfIGok0R2OaYavb6fprBhrMVKCNZBf/iHs8ORQnE+1ynozoWM1vIrtkRjl+qBBWMF0kghSnCCA==",
}

// Windows_5_0_0_mute_test_1_1571396541 is Windows 5.0.0-mute_test.1, build 1571396541.
var Windows_5_0_0_mute_test_1_1571396541 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-mute_test.1 [Build: 1571396541]",
	Sign:     "+ZNWBfOjbwPZfhgGq2AQKTZBdibC9z8WKOAQUWCCatoHvK2EmKkIYsu0xZ4uk2n121AnCOeJU9ZhZejN2W9sAA==",
}

// Windows_5_0_0_beta_7_1571421490 is Windows 5.0.0-beta.7, build 1571421490.
var Windows_5_0_0_beta_7_1571421490 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.7 [Build: 1571421490]",
	Sign:     "0KhU3qhKUZSX8xAWLgCaPXu79njWsy6aAyHW7n9keeCwd3lLdcn+6i4kb9GefC6Q3jZOslTCCAvtBw+jwOliAw==",
}

// Linux_5_0_0_beta_7_1571421490 is Linux 5.0.0-beta.7, build 1571421490.
var Linux_5_0_0_beta_7_1571421490 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.7 [Build: 1571421490]",
	Sign:     "XzAJwiiURMVqlo4UXDl/svVFxc5ne1VutLhkZDT2UG2QWsvFUMqTej+6EAeoaAimyN5zzoO5/mR9TBEsedFFDw==",
}

// MacOS_5_0_0_beta_7_1571421490 is macOS 5.0.0-beta.7, build 1571421490.
var MacOS_5_0_0_beta_7_1571421490 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.7 [Build: 1571421490]",
	Sign:     "dNz3jnxhGwSLKTRi+R8nWAiotG8y3o/MtxcAVUGl5WgSCOBPIh6W9Lffeqdi2mq/NAq/n5b/w9rNuTIPK47eBA==",
}

// Windows_5_0_0_beta_8_1571671044 is Windows 5.0.0-beta.8, build 1571671044.
var Windows_5_0_0_beta_8_1571671044 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.8 [Build: 1571671044]",
	Sign:     "heRyC/ws7xD/RCMv+voQ69zpKKx00pAnPpQGSp4DqZvwmInG3/5jDaDbD+dD47BlDlpPmd7Qj9/qHkty1VtwCw==",
}

// Linux_5_0_0_beta_8_1571671044 is Linux 5.0.0-beta.8, build 1571671044.
var Linux_5_0_0_beta_8_1571671044 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.8 [Build: 1571671044]",
	Sign:     "ANXPHY1ZJlhEPAxngYChDm3XRU0XZntITzHlnZmBGRQOednkyAeZV+/DthWmYmgd0diJt1+qTnI3LNyB8PcUBA==",
}

// MacOS_5_0_0_beta_8_1571671044 is macOS 5.0.0-beta.8, build 1571671044.
var MacOS_5_0_0_beta_8_1571671044 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.8 [Build: 1571671044]",
	Sign:     "d3Jh4QELTkUXMJBunpw6816XB89iHxTPONFDXCMaiCIlthWpmYpN4mOi4+RZKlTtyzShP6cyQ/quN9Lvpm5iCA==",
}

// Windows_5_0_0_beta_9_1571949734 is Windows 5.0.0-beta.9, build 1571949734.
var Windows_5_0_0_beta_9_1571949734 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.9 [Build: 1571949734]",
	Sign:     "m04/1RI/r2RM6aHwRrvENlB0/Px6UnZwE2Lqo7IgQiB4MpFRmAgMu7g/gVB9NdWeMdhm5ulsM5lyYrcu7dyfBA==",
}

// Linux_5_0_0_beta_9_1571949734 is Linux 5.0.0-beta.9, build 1571949734.
var Linux_5_0_0_beta_9_1571949734 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.9 [Build: 1571949734]",
	Sign:     "b6ksNapJZndbf5qa1dcvqRgCdcgay0KQrnw8IYkPAXY/OvccuoJ/LUfg/a01nXbxbh45kp7h5gTk9l0L9NVPDQ==",
}

// MacOS_5_0_0_beta_9_1571949734 is macOS 5.0.0-beta.9, build 1571949734.
var MacOS_5_0_0_beta_9_1571949734 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.9 [Build: 1571949734]",
	Sign:     "Y+qroeb12dDsCO+OTuoERTLgTUWihZ076cODxmo6iyNPPVS9xy1zq8hv1lEtc4UcC3EAqusBRS2ikKY6PnsdAQ==",
}

// Windows_5_0_0_beta_10_1572213852 is Windows 5.0.0-beta.10, build 1572213852.
var Windows_5_0_0_beta_10_1572213852 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.10 [Build: 1572213852]",
	Sign:     "2xg5JB8a1KTy9R/kXvnsW4rBpGzOPnUSREf80r4vM9KYSj0qj0x4dvFU5Ny/w3Kiq0OKAlvG24cSiKk0R0TjDQ==",
}

// MacOS_5_0_0_beta_10_1572213852 is macOS 5.0.0-beta.10, build 1572213852.
var MacOS_5_0_0_beta_10_1572213852 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.10 [Build: 1572213852]",
	Sign:     "Xtdmc5N1VOdedl10R+vZfxpNR1mRiuraEvP/wzZanttYkhKWvjR5kciXG3lLhLvb0D6q3lKfz7mBB4ejbhhvDQ==",
}

// OSX_3_5_0_1572274459 is OS X 3.5.0, build 1572274459.
var OSX_3_5_0_1572274459 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1572274459]",
	Sign:     "lRiaeecTWNnnipJ/O+n4DjHUK0C8hOc/3/G9ekOvhudNIkU8XwyXGuT+fR1l9SBO7VqwaZHRQcSJX0Nc0wVjBA==",
}

// Windows_5_0_0_inbox_update_test_3_1572358097 is Windows 5.0.0-inbox-update-test-3, build 1572358097.
var Windows_5_0_0_inbox_update_test_3_1572358097 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-inbox-update-test-3 [Build: 1572358097]",
	Sign:     "94cs11YdtF8xxTa/aOrdm1JE5RPkZSQCo1l56qXiMpovFIqnVWisJ45Uv0FHEZCQ71w7NOQylK4u8Vz+OvOJDg==",
}

// OSX_3_5_0_1572367939 is OS X 3.5.0, build 1572367939.
var OSX_3_5_0_1572367939 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1572367939]",
	Sign:     "a92Ue4WtLHiAxcVkZK1egx4W8vMCrvlWZQFtj4FO+ouYMiICWZbMtT0MWrnEtwq6OBqkkWBTYZje0893k/rFBg==",
}

// Linux_5_0_0_017dbfce_1572429535 is Linux 5.0.0-017dbfce, build 1572429535.
var Linux_5_0_0_017dbfce_1572429535 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-017dbfce [Build: 1572429535]",
	Sign:     "Q3lpSvOgLIPQywUWX0okUdBhUD6W90OLbTEYwSFDKBQ+5neHf/ziBLoJ2jDegMXO3KShpMgsJIAS/qjsP73tDQ==",
}

// Windows_3_5_0_1572447082 is Windows 3.5.0, build 1572447082.
var Windows_3_5_0_1572447082 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1572447082]",
	Sign:     "igVHTt+UUyZDHQpj8sEm3fGw+r+MDVkspQKPS/+fsxiVJr1vy2LpDQlpeZ7Yr6C6eECtCx7He58DXALTQD7JAg==",
}

// Linux_3_5_0_1572447082 is Linux 3.5.0, build 1572447082.
var Linux_3_5_0_1572447082 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1572447082]",
	Sign:     "/5nJG7aByRNQKpUapx+cd7EQS80iEA9B+8z1bQgkrkopYfpYJD3PioUaI4oNCvdyq5I2ROheOcaHMTI9M7duAw==",
}

// OSX_3_5_0_1572447082 is OS X 3.5.0, build 1572447082.
var OSX_3_5_0_1572447082 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1572447082]",
	Sign:     "H20O0S/45t4TerVsFDNAOXr5yD5VrI7Ps3Nx0RFyPwubYUWXDiIj+LO4wu8wbuxag9V2VJKxtAax1OVWYZssAw==",
}

// Windows_5_0_0_test_1_1572609725 is Windows 5.0.0-test.1, build 1572609725.
var Windows_5_0_0_test_1_1572609725 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.1 [Build: 1572609725]",
	Sign:     "MJvx4bAduHXmC1AAX+w6Lv4vHAUatzBXfKhtJIV9SDKd/q98BIJWEkGCuBXEdBzk9VXfcTpLUefz47BPSQ8RCA==",
}

// MacOS_5_0_0_test_1_1572609725 is macOS 5.0.0-test.1, build 1572609725.
var MacOS_5_0_0_test_1_1572609725 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.1 [Build: 1572609725]",
	Sign:     "axyql5RDoqUxtZkbPY+Jw7uJgd0n/Rz8LeBbdu+Tj6mW3A0U0u+wPpc7qg2OWA5dRHQ0Ut+VF9okXbsI5PKwDA==",
}

// Windows_5_0_0_beta_12_1572868115 is Windows 5.0.0-beta.12, build 1572868115.
var Windows_5_0_0_beta_12_1572868115 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.12 [Build: 1572868115]",
	Sign:     "w8i8mSIJ3y6wnFxSp8Gh6CRl3i8Q5owzchsHefG3kKYqzm2oyYsMDOsX61FVELbyiQoQea+QJZgGHY+MZCTCAQ==",
}

// Linux_5_0_0_beta_12_1572868115 is Linux 5.0.0-beta.12, build 1572868115.
var Linux_5_0_0_beta_12_1572868115 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.12 [Build: 1572868115]",
	Sign:     "IjTT7wlPMm5/hORA7KY2Jl1WmpzUzVyGW1hn0lBfzfkCyHk0N+9S/T2l75CvsNf/oetkzyr6J4YNK/XUszbqBQ==",
}

// MacOS_5_0_0_beta_12_1572868115 is macOS 5.0.0-beta.12, build 1572868115.
var MacOS_5_0_0_beta_12_1572868115 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.12 [Build: 1572868115]",
	Sign:     "SGNeBOp9Gy2rfT83IWOy76J1EK0h5GMEdXNZ6Hiuo22Bk+6UVRCVYUkrC0iyIdlxqug6Oy6xLTVn/IDQ97pCAQ==",
}

// MacOS_5_0_0_test_2_1572958346 is macOS 5.0.0-test.2, build 1572958346.
var MacOS_5_0_0_test_2_1572958346 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.2 [Build: 1572958346]",
	Sign:     "mtAt2UpaOYxOgoNkcMyCGvvRCRHjCd+kRpCeFT5s4lQZQk6E4WCc5Sy7pdAB2SMTqBGljlLijbVq8R1EdTwhAQ==",
}

// MacOS_5_0_0_beta_13_1572974727 is macOS 5.0.0-beta.13, build 1572974727.
var MacOS_5_0_0_beta_13_1572974727 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.13 [Build: 1572974727]",
	Sign:     "YD9BfBDOgtH275S4yvRKehjnWropCs+PLjQXVFnCFYMiR+cNdp93LAABFqjFIA/oilR3CyhqZj3gFHxNbHLWBw==",
}

// MacOS_5_0_0_test_3_1573037288 is macOS 5.0.0-test.3, build 1573037288.
var MacOS_5_0_0_test_3_1573037288 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.3 [Build: 1573037288]",
	Sign:     "+AqLKfemvASC0sYMz7/G1J5Yhf2/M3Te4/kYrsCgsq39zUxcViLJoJ/B0Poz3R5Q6vpugSpYvzGM4g2x3eBWCg==",
}

// Windows_5_0_0_test_6_1573147021 is Windows 5.0.0-test.6, build 1573147021.
var Windows_5_0_0_test_6_1573147021 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.6 [Build: 1573147021]",
	Sign:     "3DvO3eqDDRQmch2WEvZhf398j2EcTDzZl/IlDdWUVDO5HvuIxsAsiOQIap+Kgow8IpsE18psIPXxQReaVlR6Ag==",
}

// MacOS_5_0_0_test_6_1573147021 is macOS 5.0.0-test.6, build 1573147021.
var MacOS_5_0_0_test_6_1573147021 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.6 [Build: 1573147021]",
	Sign:     "7NY9EOPggMqcGPW66i0sl/xJPCPm4UIZoMbOGoYRbr0+SiiMu6LMj4+PnHyaLgEQgf6dQNYsCXLgs85/1DbPAw==",
}

// Windows_5_0_0_test_9_1573214586 is Windows 5.0.0-test.9, build 1573214586.
var Windows_5_0_0_test_9_1573214586 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.9 [Build: 1573214586]",
	Sign:     "euaWnuS9dG+QcbOdxXl3EjVvw4C429+vPih5iqSvKGHiFP4lWRfhokHxMhl/6GXfdH57ofTEwaEYQ+SYiPMfAg==",
}

// Windows_5_0_0_test_11_1573316935 is Windows 5.0.0-test.11, build 1573316935.
var Windows_5_0_0_test_11_1573316935 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.11 [Build: 1573316935]",
	Sign:     "bLObW+PicJcWKpi+RsTc9v+sdNokL+LuKvkB9zbT4LDb+C7ygKZxW36eF/tnlOz+k/c+1K6pw2WiGYWEAr8BAg==",
}

// MacOS_5_0_0_test_11_1573316935 is macOS 5.0.0-test.11, build 1573316935.
var MacOS_5_0_0_test_11_1573316935 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.11 [Build: 1573316935]",
	Sign:     "b/eiifmXVqQ63MEYo99zmBU+ePyZxYjHapCp8lRxxqay4S7IYmLO/L0hsuUwuhufU3NRXBgSafPXY/qM72MQCw==",
}

// Windows_5_0_0_test_12_1573502287 is Windows 5.0.0-test.12, build 1573502287.
var Windows_5_0_0_test_12_1573502287 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.12 [Build: 1573502287]",
	Sign:     "fmzYSYWzKZv0BuQ8UZaTqjAEEnURd2BuD+cXRtNJU3GaI3OdDQ2/1CsbaqoMaA7csc4Q7Mmwp06CddRRGoj1Cw==",
}

// MacOS_5_0_0_test_12_1573502287 is macOS 5.0.0-test.12, build 1573502287.
var MacOS_5_0_0_test_12_1573502287 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.12 [Build: 1573502287]",
	Sign:     "aSZbUd87Fm8nZBGZBGlrBevVtnS9kh1FLzAMdux9xL+4XT72WSdw/xxvrseuY/QRxLhQXjDIfrIk5r3A9lXSAQ==",
}

// Windows_5_0_0_test_16_1573563185 is Windows 5.0.0-test.16, build 1573563185.
var Windows_5_0_0_test_16_1573563185 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.16 [Build: 1573563185]",
	Sign:     "GtKDGT9AZueVNfCXAggCQVlRDO+SaDiy0gbhJvDkp/uSmhD9oO1PUcJUG1ma9yuvykxaIQNvd8PjgIlUux8jAg==",
}

// Windows_5_0_0_beta_15_1573580845 is Windows 5.0.0-beta.15, build 1573580845.
var Windows_5_0_0_beta_15_1573580845 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.15 [Build: 1573580845]",
	Sign:     "h4X53sXhFBAewG3RJPqxj/LJHjSeheMtFp1/ZIJ3uYrpJ081SqCHqdmabg5JdKiXX81jQFBy/v7l+mtEbX/hCA==",
}

// Linux_5_0_0_beta_15_1573580845 is Linux 5.0.0-beta.15, build 1573580845.
var Linux_5_0_0_beta_15_1573580845 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.15 [Build: 1573580845]",
	Sign:     "WQu3TToFKUCviY0m91nruqCIcGt4tPwz0oEiyv80ujabD17rA9F7JK24BytwdmsDaVGVuUkMb6VXfWo9HldqCA==",
}

// MacOS_5_0_0_beta_15_1573580845 is macOS 5.0.0-beta.15, build 1573580845.
var MacOS_5_0_0_beta_15_1573580845 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.15 [Build: 1573580845]",
	Sign:     "h0a42YDAzJnIYoU36COe372buvPI0QDwVW77NPy3XYrg2LjxkJH86sNmE/tkG13Fbtl9jgczFADkVxR7nDSgBQ==",
}

// Windows_5_0_0_test_17_1573581231 is Windows 5.0.0-test.17, build 1573581231.
var Windows_5_0_0_test_17_1573581231 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.17 [Build: 1573581231]",
	Sign:     "FbaymngIJXw8PmYIM0AeSyK/589RSgjoc8J4/fN2pdKL0J1W+LKHq0NIOY9CkltrDASyHMOTLU2XAk6iZj6gCw==",
}

// Windows_5_0_0_beta_16_1573593194 is Windows 5.0.0-beta.16, build 1573593194.
var Windows_5_0_0_beta_16_1573593194 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.16 [Build: 1573593194]",
	Sign:     "/rYy1w+7+Ifb3k9PADIRdbDP+3vISZIFL0q9yh9+6xy6XJV5lJm2U+WqC9fKKto3J+y7pT4tqHnICzSUzcVnCg==",
}

// Linux_5_0_0_beta_16_1573593194 is Linux 5.0.0-beta.16, build 1573593194.
var Linux_5_0_0_beta_16_1573593194 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.16 [Build: 1573593194]",
	Sign:     "vrwdwFiG2FGhjkfzAS08poN7aU6Y+JT8XQODY4z9QauNe5FWVQlQBCasZe161c0vlEw5CEtN4ObnYu7BtAHRAA==",
}

// MacOS_5_0_0_beta_16_1573593194 is macOS 5.0.0-beta.16, build 1573593194.
var MacOS_5_0_0_beta_16_1573593194 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.16 [Build: 1573593194]",
	Sign:     "FdJ/YMChBoySv+ylNpmi8IFyh933MNTw51ymfks8BiVoAkEn2v9ieBLlApm/2XhhvWbe4TQdd/STu3SeEMepAA==",
}

// Linux_3_5_0_1573741018 is Linux 3.5.0, build 1573741018.
var Linux_3_5_0_1573741018 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1573741018]",
	Sign:     "K69Ycxkm2mMkmnx2Z3H/tcexuwhxUCKdCf2HR+2ZYUysEssCI/xCMV5IyVeNtseX/Rj2rKFyU202XvtZvwuHAQ==",
}

// OSX_3_5_0_1573741018 is OS X 3.5.0, build 1573741018.
var OSX_3_5_0_1573741018 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1573741018]",
	Sign:     "6fE/E5qKkXV9fMMEZoz2RqdHKA1jLAP3pRGDcFgIWZWhAgJ62S7zpjbjfyu5ei8zTf0uKrU6z0X8e+rb3M1/CA==",
}

// IOS_3_5_0_1574093735 is iOS 3.5.0, build 1574093735.
var IOS_3_5_0_1574093735 = ClientVersion{
	Platform: "iOS",
	Version:  "3.5.0 [Build: 1574093735]",
	Sign:     "bCdY6e88YBCF7lpScGsVO3AWhKFHvj4TiaXftRC2RKDo1N/5FS3QS3/A9KAQDx55P4CdwN1qfbMmlFJQcXJ2CA==",
}

// Windows_5_0_0_test_18_1574258541 is Windows 5.0.0-test.18, build 1574258541.
var Windows_5_0_0_test_18_1574258541 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.18 [Build: 1574258541]",
	Sign:     "LlcASnWNx904WXYagFMJtawQmlhxr1BVexhXUHPeIuXl9GNKs+dZvT9PhzM93yUDTLQPQ2TzPl0vx9+yxZX1DA==",
}

// Windows_5_0_0_test_19_1574273002 is Windows 5.0.0-test.19, build 1574273002.
var Windows_5_0_0_test_19_1574273002 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.19 [Build: 1574273002]",
	Sign:     "26qGf4496+sTJsj36BNN1Q2Vt51DCgwddXGM0zwM4/RQo94/xtxEM0jOIcDoudkQU9Yh/dAUY5V+N/E809mxCw==",
}

// Windows_5_0_0_test_20_1574327385 is Windows 5.0.0-test.20, build 1574327385.
var Windows_5_0_0_test_20_1574327385 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.20 [Build: 1574327385]",
	Sign:     "rdeWaZq1Nej5HjEMi9mCKUiQCJAdTxyaCZY9zaTmZu0H6tub28Tn1LXmsQ+9tcKSrJNGbNfjzC8d20DLNwkUBA==",
}

// Windows_5_0_0_test_21_1574343180 is Windows 5.0.0-test.21, build 1574343180.
var Windows_5_0_0_test_21_1574343180 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.21 [Build: 1574343180]",
	Sign:     "IK5/oVWmpkDcN2q1Z0Or79aHtWBZEIVtiVssQhpNQUItD5KBbsv36pDOwFRwuVPgngv9Rq2XJKOd0kL/yGSCAA==",
}

// Linux_5_0_0_test_21_1574343180 is Linux 5.0.0-test.21, build 1574343180.
var Linux_5_0_0_test_21_1574343180 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-test.21 [Build: 1574343180]",
	Sign:     "ZtHZonfg6g84zkbp3aiiv5wb2L0G76UusiNCJkAS3q3RXHNQ1zCLWiCRbfskIoXlGqn3qJBQdNy92HSK4tbjAQ==",
}

// MacOS_5_0_0_test_21_1574343180 is macOS 5.0.0-test.21, build 1574343180.
var MacOS_5_0_0_test_21_1574343180 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.21 [Build: 1574343180]",
	Sign:     "fsSlh0n45LwmkUsZ56OgzhKtAmX5DU04Kzxl4EuytwD4Q8HQ4660V1ue1rBNQx/YIFKLlC7FIF3qMTT6LBjwBA==",
}

// IOS_3_5_0_1574357871 is iOS 3.5.0, build 1574357871.
var IOS_3_5_0_1574357871 = ClientVersion{
	Platform: "iOS",
	Version:  "3.5.0 [Build: 1574357871]",
	Sign:     "9m9E+yrIfJKmRDvujRH5IsbHXClEbgm9zRms+iL9ikLhiM1gzIBWBVVUKFqmtpSSZDq3lnmkN9DmaC8gxhvPBw==",
}

// Windows_5_0_0_test_22_1574873227 is Windows 5.0.0-test.22, build 1574873227.
var Windows_5_0_0_test_22_1574873227 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.22 [Build: 1574873227]",
	Sign:     "6m8Nob+e14ECagLHedtLc2iiNP8lm2eTOH1E5xBq8EW8EYpvUaWFsErg+pcjCDDruwlzlrrryrvJUGnhEKzjAQ==",
}

// Windows_5_0_0_test_23_1574935289 is Windows 5.0.0-test.23, build 1574935289.
var Windows_5_0_0_test_23_1574935289 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.23 [Build: 1574935289]",
	Sign:     "n06nZYaCKCoqwYGi1pC6/v91SgojFrNXazJZzz1DJm4XK+utmCQikAMzJdXe76n0rfeNvAs2BQ35wiKAlSodAA==",
}

// Android_3_5_0_1574942993 is Android 3.5.0, build 1574942993.
var Android_3_5_0_1574942993 = ClientVersion{
	Platform: "Android",
	Version:  "3.5.0 [Build: 1574942993]",
	Sign:     "hfTN8OfwUhPZSgkDgLGZROwUfolrK8/ep0wXOIcSk+RM3rB9nrh6tpISemmJJDfUV3Cl99ySF/vs4WjIlICoCQ==",
}

// MacOS_5_0_0_test_24_1575287495 is macOS 5.0.0-test.24, build 1575287495.
var MacOS_5_0_0_test_24_1575287495 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.24 [Build: 1575287495]",
	Sign:     "i40fx8lABCbJkHxFNh4HYYXXLJXM/aouoeC/Wfj3G9IOCc7D9twKMAgm8l2Zbay2n4Xk56V+L0jWctasVc59Ag==",
}

// Windows_3_5_0_1575318320 is Windows 3.5.0, build 1575318320.
var Windows_3_5_0_1575318320 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1575318320]",
	Sign:     "NSByceYLl/b8kB8+gDgoFdUJkfavpCHQ4sWv0qpP6qjIHT6izqx3IuzAR8Ma6opV117yASpr9R2RrOZBN/lhAg==",
}

// OSX_3_5_0_1575318320 is OS X 3.5.0, build 1575318320.
var OSX_3_5_0_1575318320 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1575318320]",
	Sign:     "srhE2XU7hB2WWBdzywlnH3q+cSWxBTBR+oISy8+jHHeCKjg0uUHIFUtqpnk/8xbvpykRJs6rW6e17ax4AiPeAA==",
}

// Windows_5_0_0_test_25_1575368044 is Windows 5.0.0-test.25, build 1575368044.
var Windows_5_0_0_test_25_1575368044 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.25 [Build: 1575368044]",
	Sign:     "BOP7V84ukRS1fs/wuAMfZC9qM/c17Kpf7bkuHnzSjCbVu+rMlxrb/6uWE/wCR31pUS9/oUMQIDwCOhbkUTbIDg==",
}

// Windows_5_0_0_test_26_1575420598 is Windows 5.0.0-test.26, build 1575420598.
var Windows_5_0_0_test_26_1575420598 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.26 [Build: 1575420598]",
	Sign:     "FSI7yKzzU96ftITn2uUKBV+S03rk4y/wAAdpLjoEMMzuVSoJrGAOu0hiu+TwaqO15ECbhKdti6ClYv49O59/Dw==",
}

// Linux_5_0_0_test_26_1575420598 is Linux 5.0.0-test.26, build 1575420598.
var Linux_5_0_0_test_26_1575420598 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-test.26 [Build: 1575420598]",
	Sign:     "56IHXOCLPt3AgTc138PmVGMWpHwupetm2SfRtGezjVAs1O7O507sEGbpzTYbL7HHqXp7kAGv7dJB1AZNm1CJDA==",
}

// MacOS_5_0_0_test_26_1575420598 is macOS 5.0.0-test.26, build 1575420598.
var MacOS_5_0_0_test_26_1575420598 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.26 [Build: 1575420598]",
	Sign:     "HJQkHM529e2eHdejAIEx4ICYpP9lqClnvyIyo3XMNKcR9Udw2WfUetfCD6VD0DmOygkU/vmI6O2re7EAC/MEAQ==",
}

// MacOS_5_0_0_test_28_1575626623 is macOS 5.0.0-test.28, build 1575626623.
var MacOS_5_0_0_test_28_1575626623 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.28 [Build: 1575626623]",
	Sign:     "CXzUmy7PP5985/QDw7ysWktG/mlhYeN0NovrOYaBNVN6zqJOYskupSud5Pc5Nxj9PiY8gIBc/8fZJ+FSJGY7DQ==",
}

// OSX_3_5_0_1575804173 is OS X 3.5.0, build 1575804173.
var OSX_3_5_0_1575804173 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1575804173]",
	Sign:     "VnPAOJE+AIi8WOMBz4ym+PCOQoFdwfp86rYX7u2VZK63OrUZ/aRpKF0v0Lwbn4jywPjL1bt3RJ+trP9+cdyiDQ==",
}

// Windows_3_5_0_1575870843 is Windows 3.5.0, build 1575870843.
var Windows_3_5_0_1575870843 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1575870843]",
	Sign:     "RDv4LfYSy9Cr/uQmLh7zk5Smce5aYYAGYbZCAXJLK/tlOlXwzqxoCXor/Dtg9XhjAkVeXSdX+ZAaHwLuy1vvBg==",
}

// Windows_5_0_0_test_29_1575906492 is Windows 5.0.0-test.29, build 1575906492.
var Windows_5_0_0_test_29_1575906492 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.29 [Build: 1575906492]",
	Sign:     "QCZAnoRiStjO5epvXlTvq0R3YHD3t6VMTOSzqdAdIooJMWiOMP0TMujDmDPZK344CJt6/wBTWz61cYge3nECAw==",
}

// Windows_5_0_0_test_30_1575953901 is Windows 5.0.0-test.30, build 1575953901.
var Windows_5_0_0_test_30_1575953901 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.30 [Build: 1575953901]",
	Sign:     "rxTi0v79PMTDhbfdAZPol/BC/a+wFO5o1p75BbDJs+TDeM7/PjdkG5KySkkUbF+G5oDrLifSfANP/iUpvaenAQ==",
}

// Windows_5_0_0_beta_17_1575970903 is Windows 5.0.0-beta.17, build 1575970903.
var Windows_5_0_0_beta_17_1575970903 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.17 [Build: 1575970903]",
	Sign:     "KTcasAx1nTBvGMIQt28UfyHmCRZzuzx0vIWR2FpCaytWPYyTVe2w/u9nWH5A+e9RFJw5pphwOwZC8EBrM5OCCw==",
}

// Linux_5_0_0_beta_17_1575970903 is Linux 5.0.0-beta.17, build 1575970903.
var Linux_5_0_0_beta_17_1575970903 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.17 [Build: 1575970903]",
	Sign:     "OxacBnZqUSwz5584fVxlK+odEKXG2RxUGVQVKNw3I5Hw+/vjLThjinxZcCQeoaQVJB8jQBCKpIqDBDAoueaTCA==",
}

// MacOS_5_0_0_beta_17_1575970903 is macOS 5.0.0-beta.17, build 1575970903.
var MacOS_5_0_0_beta_17_1575970903 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.17 [Build: 1575970903]",
	Sign:     "c21ZfbMiZ9yWBhyXR5YzRWWyYAFYOgwSPbEkSEx0rnHkG59ovGEMjffBqB+a6lPItCjwep9poOrXdverrL4pCA==",
}

// Windows_5_0_0_test_31_1576066245 is Windows 5.0.0-test.31, build 1576066245.
var Windows_5_0_0_test_31_1576066245 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.31 [Build: 1576066245]",
	Sign:     "PdaEUU+pjbWv50o+rwnbC8VA9CtDLEZ3FW8s1jBbebebyNmMgJxJMbtwDii5Gh8J7KJUzG+kRTvx/KHqEY63BQ==",
}

// Windows_3_5_0_1576090604 is Windows 3.5.0, build 1576090604.
var Windows_3_5_0_1576090604 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1576090604]",
	Sign:     "tPCBJ+gtkMQZI+EZSotMjoofEDY3AothGzxijDm9U8RNpZT9CLzr0eCfz70YVVwtg50j85iDVe/l5Ss22ef4DA==",
}

// Windows_3_5_0_1576181443 is Windows 3.5.0, build 1576181443.
var Windows_3_5_0_1576181443 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1576181443]",
	Sign:     "XOVRDA3D2gvGUKmpuuCszuBCyyjUQUxvaGCN5EGidbNhOzJ6cPMPLgcAXXGn/itPGWjCSxZM8muucsgigwPxCw==",
}

// Windows_3_5_0_1576513599 is Windows 3.5.0, build 1576513599.
var Windows_3_5_0_1576513599 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1576513599]",
	Sign:     "aVC4Jfjl8REU2dunFeHYH6KKp8jN0QEb6Q58VOveVMlm/YmaEPzNS7dDEew/rroLcDzN0XJkC6wqBtKdAt2jAg==",
}

// Windows_3_5_0_1576585064 is Windows 3.5.0, build 1576585064.
var Windows_3_5_0_1576585064 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1576585064]",
	Sign:     "l04dlaw8vwImq58v5cg7C2ZbxCAEjStAsi334u6Wf6c668u9DuEDeAGLhxDSPe/ZjsSUAGavkYJXgqtdzTFoCw==",
}

// Windows_5_0_0_test_32_1576586323 is Windows 5.0.0-test.32, build 1576586323.
var Windows_5_0_0_test_32_1576586323 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.32 [Build: 1576586323]",
	Sign:     "gaYHucbKUEFL3aHeeorqt2ECkTdBHR/A1onihLE8v07Kw1NT8b+/CWRnWMlXYxCQOyirWRFDRzJJSbRWfBXaBw==",
}

// Windows_3_5_0_1576687348 is Windows 3.5.0, build 1576687348.
var Windows_3_5_0_1576687348 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1576687348]",
	Sign:     "ip1R1gGEy38Ce7qxs5IB53EBpuPqFg08mFw49uUzWWgsvdu0l87CTtNdDeF3kRxUeDvjGVqG30CVq12B7gd0DQ==",
}

// Linux_3_5_0_1576687348 is Linux 3.5.0, build 1576687348.
var Linux_3_5_0_1576687348 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1576687348]",
	Sign:     "rWCTNfEyCRtwYMxJXOZ6+i3KIxKvBjzSnzkmJF46CHEDBg39JrozRXa149Ognps9LLGbMhouXkVjdFCivN6qAQ==",
}

// Windows_5_0_0_test_33_1576756659 is Windows 5.0.0-test.33, build 1576756659.
var Windows_5_0_0_test_33_1576756659 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.33 [Build: 1576756659]",
	Sign:     "qkP3ea5HOWUOvqK0OQYlB+IgAvwai412cfpayxiJ5k/UiFnc0wFDzIMXL+9ZNi/UoyMKWmjy/KcYuLFHGI8wDg==",
}

// MacOS_5_0_0_test_33_1576756659 is macOS 5.0.0-test.33, build 1576756659.
var MacOS_5_0_0_test_33_1576756659 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.33 [Build: 1576756659]",
	Sign:     "JiNrdoUplbYfox6cyRj3K2HitEzWdkKx91xcbpH5iPr6BlFQbmfsXfVGtNWol8YCls1EkDKXN1zPewVsN9KpAg==",
}

// Windows_3_5_0_1576757477 is Windows 3.5.0, build 1576757477.
var Windows_3_5_0_1576757477 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1576757477]",
	Sign:     "QRpkkp0eeFNsdhg+8UpCwpTIqeMZbcmRkjRBAwjWklk5ycO58a/jxtkfl1vth1DvG5lRUd0ar/ZIEVwkJhalCw==",
}

// Linux_3_5_0_1576757477 is Linux 3.5.0, build 1576757477.
var Linux_3_5_0_1576757477 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1576757477]",
	Sign:     "lwBJK+yboe1k6rCKG5pg4AZhAM4heFMxqvvJMbhxaH3ORWOyPebQu2vkJBkVeRjGU6YUu6uS4ahlxlxdT4m0Ag==",
}

// OSX_3_5_0_1576757477 is OS X 3.5.0, build 1576757477.
var OSX_3_5_0_1576757477 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1576757477]",
	Sign:     "2o4tJcBZ+m6evtUlAXzbPHzB1aqr4JdkKFs0sC5GTyIcW9runz58aEA5HxYyl1Y5Bua1LfO+856agJDIMFxBAQ==",
}

// Windows_5_0_0_beta_18_1576838043 is Windows 5.0.0-beta.18, build 1576838043.
var Windows_5_0_0_beta_18_1576838043 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.18 [Build: 1576838043]",
	Sign:     "hKp/R33NhawXiUKIRw4XU7ovpMDRK8YU4MLW+MwcA3a9TSJLahjZ8vWJaLHdexh4ehH13VpqLiKifjzEI9KyAA==",
}

// Linux_5_0_0_beta_18_1576838043 is Linux 5.0.0-beta.18, build 1576838043.
var Linux_5_0_0_beta_18_1576838043 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.18 [Build: 1576838043]",
	Sign:     "dGtZXFeoReweKxKIr6O1xkaVvhucxgfDsmvotYQSeRww5k1GjWelPzBLC+tMxi+HjfW4pLbNl/zy/q+p4SGXAQ==",
}

// MacOS_5_0_0_beta_18_1576838043 is macOS 5.0.0-beta.18, build 1576838043.
var MacOS_5_0_0_beta_18_1576838043 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.18 [Build: 1576838043]",
	Sign:     "hAVRVqR5Diiep7ON9a52mXbTIsXLrnXSDtYHWL0vI2vtmX2Cggl5OHTzXQdqpzlEPA4vB/oR6MnKJPwiaHz4Aw==",
}

// Windows_3_5_0_1576948785 is Windows 3.5.0, build 1576948785.
var Windows_3_5_0_1576948785 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1576948785]",
	Sign:     "rDVnECt+GZtObMTx+reMnLI6Qpj09snDUDqEB9w8sfO9vZGvQEQG/WGZS+UdaT6RWeib21VD46YXq6nCKej4Ag==",
}

// Windows_3_5_0_1577821118 is Windows 3.5.0, build 1577821118.
var Windows_3_5_0_1577821118 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1577821118]",
	Sign:     "eehDiOfKnpcqsAsAn+Bfw+WR2MQiLhQb5/acupyIqn4BNTAL9c9Ezd5miYBR67P1+cNEMb9OMO05XdKqN4nWAg==",
}

// Windows_3_5_0_1578164171 is Windows 3.5.0, build 1578164171.
var Windows_3_5_0_1578164171 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1578164171]",
	Sign:     "ttMvW/20CHr6WYqUpz2uTMMsajuyHsvw4rHrMFwDBBd5yy+3wxbCgEMAZuFxqfUagsBIW8PMzowUMhSkjPvvAA==",
}

// Windows_3_5_0_1578400308 is Windows 3.5.0, build 1578400308.
var Windows_3_5_0_1578400308 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1578400308]",
	Sign:     "8Jg14dG4+TkuBMbiSB58qV6zHmX3c4yDdjuwZ+5CO0wNkyrsUWcdMTUD501XnP3cPqTQViy+3uclUA2vkZSKAg==",
}

// Windows_3_5_0_1578417881 is Windows 3.5.0, build 1578417881.
var Windows_3_5_0_1578417881 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1578417881]",
	Sign:     "VSrAXQ1ps+hvIDAC9fzMjmG573M8XsIWD0JpV1BNmccZV9uMmL5EetGnDfaZDydxFj2g7wy5SEATDGuxwA7JDg==",
}

// Linux_3_5_0_1578417881 is Linux 3.5.0, build 1578417881.
var Linux_3_5_0_1578417881 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1578417881]",
	Sign:     "ir3dtCoP7swQmDsEybluSgEAUApwZT2c626L6AqkEQd116EXoLEZvSJCNE0L+PyuTAJV07k3L89jdkCr1msAAw==",
}

// Windows_5_0_0_test_35_1578591798 is Windows 5.0.0-test.35, build 1578591798.
var Windows_5_0_0_test_35_1578591798 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.35 [Build: 1578591798]",
	Sign:     "pvBDfcSsiVWZhIJaiJB/gmI0ELlD9+uZqm5WdmfZHX9aL3BNsPw88xXkafzN+ohC+UzcWDCfzm6aN4yyBVgwCg==",
}

// MacOS_5_0_0_test_35_1578591798 is macOS 5.0.0-test.35, build 1578591798.
var MacOS_5_0_0_test_35_1578591798 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.35 [Build: 1578591798]",
	Sign:     "jPdrG3UfkCYUOznEln0VYCSZyxY0PgpDDIIis7ucaIxkbuljSe+3aQVECug97tipn4C6KfHc8F/JtkN5iKViDg==",
}

// Windows_3_5_0_1578609201 is Windows 3.5.0, build 1578609201.
var Windows_3_5_0_1578609201 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1578609201]",
	Sign:     "qjxevyZi/HpxdfvtpRmRBQnHUhHh0c4QmwYsU0iaWl2oy0gqD1+onwfJQCLtHJoC0NixgI9Yl11aZXnXTztQAw==",
}

// Linux_3_5_0_1578609201 is Linux 3.5.0, build 1578609201.
var Linux_3_5_0_1578609201 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1578609201]",
	Sign:     "RIfBsaQu+bCZo8jT58X+VOruTMfsBZbMO8iWd7od+nGsonEGXgMY1W7iB38jpRa0JPY2TqOpDqk2NMWjtJLsDg==",
}

// Windows_3_5_0_1578696214 is Windows 3.5.0, build 1578696214.
var Windows_3_5_0_1578696214 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1578696214]",
	Sign:     "cl3Ra0l/rKndWvhJRsmuL6c4/aKqea2N2N4URge35oYRuVu7QToTZuHjgM/xsSCxWcE5Jxud7PiBPkBxD52ECg==",
}

// Windows_3_5_0_1578859029 is Windows 3.5.0, build 1578859029.
var Windows_3_5_0_1578859029 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1578859029]",
	Sign:     "NWE9OG8DuU1I4Ki5TIPge3d0WgMv5w/g87uZTnqmW/JhuMluQfc2bJz5P8Ny0VaURmIz+H7/ZactBIl77mdhCA==",
}

// Windows_3_5_0_1578906268 is Windows 3.5.0, build 1578906268.
var Windows_3_5_0_1578906268 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1578906268]",
	Sign:     "b2EdIfdzv5bFaQEq4gOnuT87moaTH6WhaMKDGNbGUjnrJ4Px69I3BcJtvatyaGvgeYaqjzDcjqK4MeVRSzvZBQ==",
}

// Linux_3_5_0_1578906268 is Linux 3.5.0, build 1578906268.
var Linux_3_5_0_1578906268 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1578906268]",
	Sign:     "1exAxKXS5X47jT7rb7PUDIXF+vSdRvJBPIQpHB2nLivjXLxq49gBnj+BLA2KU3fWLeCAv5u4cUnixrKsZ3dUDQ==",
}

// Windows_5_0_0_test_38_1579022578 is Windows 5.0.0-test.38, build 1579022578.
var Windows_5_0_0_test_38_1579022578 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.38 [Build: 1579022578]",
	Sign:     "vVnfcWdAhVlpnba8sPH62U3R7hRGJh8wEyzbUDwjYhZdgJZj+e1k+4SINiy2XqIX8rkHeqQhLh9HKNz7xKVhAw==",
}

// Windows_3_5_0_1579162934 is Windows 3.5.0, build 1579162934.
var Windows_3_5_0_1579162934 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1579162934]",
	Sign:     "S7sriAuGvJAt/GqvEeU3qQrBbY1KabBwS6rdVr/MNkX7Qb0157vbK9UtNxe/6WaSVTWcTbU26EP6G1IL2ZHqBw==",
}

// Linux_3_5_0_1579162934 is Linux 3.5.0, build 1579162934.
var Linux_3_5_0_1579162934 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1579162934]",
	Sign:     "+7j8+3pxJ9F8RTW3cwuyPZ/ECBjIEt7skiAO6vwYi0vEURCzaRboT2wAccb5+Morc1GJLQ3TWv1+F+/FfQj7Bg==",
}

// Windows_3_5_0_1579271398 is Windows 3.5.0, build 1579271398.
var Windows_3_5_0_1579271398 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1579271398]",
	Sign:     "YQuBI583WrbI6REuuNi9xQ8qoHVBS/MZyIpzHXbJOFQcZvRIxxruvfJQChMpvc9/RehbZVe2KY8BW2nTIANcCA==",
}

// Linux_3_5_0_1579271398 is Linux 3.5.0, build 1579271398.
var Linux_3_5_0_1579271398 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1579271398]",
	Sign:     "WeJT/r4lHlsCD1SEpJ6EV+Aqfv2hVBz0sDfvfOZCQ0PIoU7NgyqeSuopvRv/YBnR5pcrTRPiUZKBXnECutiIBg==",
}

// OSX_3_5_0_1579271398 is OS X 3.5.0, build 1579271398.
var OSX_3_5_0_1579271398 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1579271398]",
	Sign:     "3HhWtyi3ehFQrMJfa1s7YCKUFf4uEMvEWLv4tU0a5R2XNAaN5xM7GqWzxAT21mYzLVZEppl8dPQZ9W5IkzhvAA==",
}

// Windows_5_0_0_test_51_1579367787 is Windows 5.0.0-test.51, build 1579367787.
var Windows_5_0_0_test_51_1579367787 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.51 [Build: 1579367787]",
	Sign:     "eCUrSXyKFRZXCfyFnOl7PR3r6VCDqzu7yytubUTTQb00jMoDbADYVHCnyc4ZUD51oHDlPWsStfczoF127BnTBQ==",
}

// Windows_5_0_0_test_52_1579512204 is Windows 5.0.0-test.52, build 1579512204.
var Windows_5_0_0_test_52_1579512204 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.52 [Build: 1579512204]",
	Sign:     "CTql2Bq7+q3TVD0/sZh8MybbQyPi2z1ygWdkKDGMXHJ/Qhio/o9Z7AXMF3fhp2+rJrdGj6CCb9X3vT1MT6B7Ag==",
}

// Windows_3_5_0_1579611798 is Windows 3.5.0, build 1579611798.
var Windows_3_5_0_1579611798 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1579611798]",
	Sign:     "p9AERgogemgDxWHzRVnq8laS/47iefIGxU+17XFXChG/gUzxHYzXA1BIPfG3zlXL/FWcuvNfWRdourPdM1JMBA==",
}

// Windows_5_0_0_test_55_1579622615 is Windows 5.0.0-test.55, build 1579622615.
var Windows_5_0_0_test_55_1579622615 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.55 [Build: 1579622615]",
	Sign:     "ah6EIrqz/rbmYCF/PAW9qF1W5qS7De7LTGc76xgEC/HwYg77nWrAk3tYE5xYJN0YUuYL6vuZvtMI5iij7SRACQ==",
}

// Windows_3_5_0_1579686935 is Windows 3.5.0, build 1579686935.
var Windows_3_5_0_1579686935 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1579686935]",
	Sign:     "TghaGBYGZwXlTXXvusH+/O0jdhOtWNdU3HcxVzg2Vsq/H5n9y6+zpHdfG/Ea282pZlPNmjAigJRPm2y/WmjeAQ==",
}

// Linux_3_5_0_1579686935 is Linux 3.5.0, build 1579686935.
var Linux_3_5_0_1579686935 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1579686935]",
	Sign:     "IhWffkHKmt/jnYeL5IQxK8BXmwcdgNTiP9Lg6RMmiiMTFq6PHvQHjQGFNOrVZSgeLpEYuIIj+0cL78rPgGUoCw==",
}

// OSX_3_5_0_1579686935 is OS X 3.5.0, build 1579686935.
var OSX_3_5_0_1579686935 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1579686935]",
	Sign:     "/TmafB2ePmpqRIcDgIyxzgSXioSQMPgiR8ATdt2AheNH4NP+MPQQ4DHtwNm5HVb7jTw+P5HfsOBVcST72kn3AQ==",
}

// Windows_5_0_0_test_56_1579699914 is Windows 5.0.0-test.56, build 1579699914.
var Windows_5_0_0_test_56_1579699914 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.56 [Build: 1579699914]",
	Sign:     "r4aN1EBSyf5EBbk6wP4E7zoKDLY2tFphEp8tTATYQIFU7geA3h54fGznbZ894gMIrnrLV2Bv/CrmftLyH6VvCA==",
}

// Windows_5_0_0_test_57_1579705006 is Windows 5.0.0-test.57, build 1579705006.
var Windows_5_0_0_test_57_1579705006 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.57 [Build: 1579705006]",
	Sign:     "LBxcwx72FKcPvfjLwtQHAuf+hcQPCRM6xQ7DV7Jxz/YAtNDdG5C7fAPrhj84XuJo1cufkQaE6fW/ucvao6s6Cw==",
}

// Windows_5_0_0_beta_19_1579708986 is Windows 5.0.0-beta.19, build 1579708986.
var Windows_5_0_0_beta_19_1579708986 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.19 [Build: 1579708986]",
	Sign:     "4hImRslbCAQhkjlbAWT5HWANA9yophaWEuE4AQ6YXh1/EY+XeyCI8+RBn1pqpDNuGE5FMBZWhGmGhoY/TaZACg==",
}

// Linux_5_0_0_beta_19_1579708986 is Linux 5.0.0-beta.19, build 1579708986.
var Linux_5_0_0_beta_19_1579708986 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.19 [Build: 1579708986]",
	Sign:     "sizcn7tabErfnzSilYrA0gFy/PPEYufUlAT+VDonx3RQz3/GE5NiM+y0Ovq6LEqMktIqkAqCfr7mAAcBgXZZBw==",
}

// MacOS_5_0_0_beta_19_1579708986 is macOS 5.0.0-beta.19, build 1579708986.
var MacOS_5_0_0_beta_19_1579708986 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.19 [Build: 1579708986]",
	Sign:     "uyzckz/x5TIm4m6G3+vqrvZ2QGqRG5VhXZIx9OATLo5WOJbmW5zzXgiZdca3w09gvfo+ab4X/psJmayXJ7vlCQ==",
}

// Windows_5_0_0_test_58_1579878094 is Windows 5.0.0-test.58, build 1579878094.
var Windows_5_0_0_test_58_1579878094 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.58 [Build: 1579878094]",
	Sign:     "lYrBlo3lKYXVFZDFaKQ1v7IfMFtoHU/BIlT5ebeAQOy18W7YyZyWoxB4EzFynmMiLTB/H7xpbqsYC2yzHCHGBg==",
}

// MacOS_5_0_0_test_58_1579878094 is macOS 5.0.0-test.58, build 1579878094.
var MacOS_5_0_0_test_58_1579878094 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.58 [Build: 1579878094]",
	Sign:     "BBuo+6vcCjeJ4bWkL5cvsuuie9dy+owt0zRBeroCBV+iHmHPirn6e29MW5qsCqMX9Vmm+GNIsxB9zgQ4z3KPDg==",
}

// Windows_3_5_0_1579960421 is Windows 3.5.0, build 1579960421.
var Windows_3_5_0_1579960421 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1579960421]",
	Sign:     "sCOi1sggRSo63qd6js7amPrQKuGs3Nr93DEuBgfCJSWMZxErXnXsAbSjhbl9UechjBx16qK61PdI5CSF1XQYDw==",
}

// Windows_3_5_0_1580143599 is Windows 3.5.0, build 1580143599.
var Windows_3_5_0_1580143599 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1580143599]",
	Sign:     "YRQLhax4q/VzwKpqkXWK3pgWIhuhJc4pv+Jd6yQxucPUiavIy7q5bWjQzAC/KsuDQSdKHqreUKjsOOl3jFFhBA==",
}

// Linux_3_5_0_1580143599 is Linux 3.5.0, build 1580143599.
var Linux_3_5_0_1580143599 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1580143599]",
	Sign:     "nAUR3VnXvxdwdeZcgdljrY/CFl68sLKUfPp5lOPe+g7YWVpW1dR//Az2t6Q+WDACbfaJXVBkYwmMzJlSlW7QDQ==",
}

// OSX_3_5_0_1580143599 is OS X 3.5.0, build 1580143599.
var OSX_3_5_0_1580143599 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1580143599]",
	Sign:     "DiIj0dFO8DYoCZOW/TfmMGkcaAdfLqqSgzbgV0nfz8/FCSnku7bpS8guaRINNQ9Majgq1Dfj9PVd2KMaucFDBg==",
}

// Windows_5_0_0_test_59_1580226872 is Windows 5.0.0-test.59, build 1580226872.
var Windows_5_0_0_test_59_1580226872 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.59 [Build: 1580226872]",
	Sign:     "7zZ5SSOInE7IVgyMw2doa1YgkptJpeVZGiFa9LGexY50HgZpG+UqqJUt7jBwbWIHxcxWIuTTrRGTpXTJfj+fDw==",
}

// MacOS_5_0_0_test_59_1580226872 is macOS 5.0.0-test.59, build 1580226872.
var MacOS_5_0_0_test_59_1580226872 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.59 [Build: 1580226872]",
	Sign:     "h3DS6ezaHx2RAhXvuHDnPexpDvR41CO3Tm/NHltNinUbtzUOOzVIClX42WHAUS0mSqD7mFTrjkMjJJyST6RDDg==",
}

// Windows_3_5_0_1580316377 is Windows 3.5.0, build 1580316377.
var Windows_3_5_0_1580316377 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1580316377]",
	Sign:     "2FEBFDRIkWw/cYRUbuSFvwADJGhZ1sCvFrZj7sZI72hrRRcCI1CYmTo/ukzWsEInAFz6rMf7qBaaOXfuU+6qBw==",
}

// Linux_3_5_0_1580316377 is Linux 3.5.0, build 1580316377.
var Linux_3_5_0_1580316377 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1580316377]",
	Sign:     "rUbvG0+ZB8HoOkYDkThOPABe5URUWuFsCC+kS+c4ZpNtC70ju6uaLuM0FbG3AGiRcVc8SX9zMzagvs1cNVtYDA==",
}

// OSX_3_5_0_1580316377 is OS X 3.5.0, build 1580316377.
var OSX_3_5_0_1580316377 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1580316377]",
	Sign:     "uRmSTbFGxBnghU7zAtS1624y8R3Vhvm9OWO5ZDwB4H9hxho+myT8ssHWwIN9VUWImXnwcFiuXS+lS1tjAV+3Dw==",
}

// Windows_3_5_0_1580593763 is Windows 3.5.0, build 1580593763.
var Windows_3_5_0_1580593763 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1580593763]",
	Sign:     "PmLXQboEcpz7jB1v/Y112W7aFAJ3ltgXzg167RJF5UqXlWKeqLC6X8cq2tGYRauQq2RiGDaToMcfBrsKlU5UCw==",
}

// Windows_3_5_0_1580672591 is Windows 3.5.0, build 1580672591.
var Windows_3_5_0_1580672591 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1580672591]",
	Sign:     "ssFQHF+iHGDizteHBEHI7It9t98RBUBXx4VuUPDsSWBPnpVR1/v5AIMnptFkSatOYP03JfTHH7ww52N9BdsMDQ==",
}

// Windows_5_0_0_test_60_1580683977 is Windows 5.0.0-test.60, build 1580683977.
var Windows_5_0_0_test_60_1580683977 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.60 [Build: 1580683977]",
	Sign:     "8Zy0uvHADWR1i3FptlvwSPvLeKsJzBgLkFDw2QLDcBJykRASDJ8LP1VxxV/pO8KLemcwNnsEDthHvtnXo2c7DA==",
}

// MacOS_5_0_0_test_63_1580751860 is macOS 5.0.0-test.63, build 1580751860.
var MacOS_5_0_0_test_63_1580751860 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.63 [Build: 1580751860]",
	Sign:     "A9h+7BIMYRncyO9oMUlQQFCsJVL0wq/ukLTBhXfF5s7JYVcmgDBaY/FGd6254ddUpJgB3aRKNhBpTuYWdx/ZCQ==",
}

// Windows_3_5_0_1580753736 is Windows 3.5.0, build 1580753736.
var Windows_3_5_0_1580753736 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1580753736]",
	Sign:     "Z/6h7jb4vbZv4ERritKcJD51sxrd5Rfb4qTP6Km320A0Gw14OoqW9Qz2AvN6htjFtgcZc533wZYve+Tf9Jt8BQ==",
}

// Windows_5_0_0_test_65_1580774583 is Windows 5.0.0-test.65, build 1580774583.
var Windows_5_0_0_test_65_1580774583 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.65 [Build: 1580774583]",
	Sign:     "Tk3I5UUdu8e4a+TaykPYeISia9SiSnYqvOFsLnCg3jx6tDH5qyPZgknB2YwVb1ULuKFOl2wHkKfYznrcyLJ0CQ==",
}

// Windows_5_0_0_beta_20_1580775353 is Windows 5.0.0-beta.20, build 1580775353.
var Windows_5_0_0_beta_20_1580775353 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.20 [Build: 1580775353]",
	Sign:     "DgxH692v8HgBp7gZmvjovF5/ho7UIW/BiGq0rE9tCGqn6qWhD9UDV6h/mQs0rQ9xGkttvoXgjaXx8Jdy6wMRDA==",
}

// Linux_5_0_0_beta_20_1580775353 is Linux 5.0.0-beta.20, build 1580775353.
var Linux_5_0_0_beta_20_1580775353 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.20 [Build: 1580775353]",
	Sign:     "zmuCstKmjd5B33D80/ZzUJPnxGArcfFfsFa2ZeuRrxjbckZ+Q6VmIsJ1zY8sHaBq0hplbrzyKF7nfE2rhTWJCw==",
}

// MacOS_5_0_0_beta_20_1580775353 is macOS 5.0.0-beta.20, build 1580775353.
var MacOS_5_0_0_beta_20_1580775353 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.20 [Build: 1580775353]",
	Sign:     "zVdI46BGmMQApIIB+wnhXrkOk0M68QwE/gwbqg27KFQqhDKBbMuBHqwA8lqDYu6cKiZIXNSEPtpriug94wlrCg==",
}

// Windows_5_0_0_beta_21_1580832125 is Windows 5.0.0-beta.21, build 1580832125.
var Windows_5_0_0_beta_21_1580832125 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.21 [Build: 1580832125]",
	Sign:     "m0or/uBBRVngzw13Vqg51y3tsLBsG4mAaHakIHCOEh3Dk9kyGavHeYYNq38i5AWRP0HKAzsngAST4yJWA+FnDw==",
}

// Windows_5_0_0_test_67_1580844878 is Windows 5.0.0-test.67, build 1580844878.
var Windows_5_0_0_test_67_1580844878 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.67 [Build: 1580844878]",
	Sign:     "DvmmonitqHF6ElwmDmiJ07pEq6zWF1Ui5mk1D7256fDwVkxmjOlTWXeBAXQY2hTZi7e0i8UL8mKntx8Aa03bDQ==",
}

// Windows_5_0_0_test_68_1580898716 is Windows 5.0.0-test.68, build 1580898716.
var Windows_5_0_0_test_68_1580898716 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.68 [Build: 1580898716]",
	Sign:     "+4HgRO1mbyi7Y7ERYf6rY2zl27PpOfOqqM2hplBpCwGYEXqk/kaDYgR2uzjE99tcJVPFkGabmRSKhpEkNuy1Cg==",
}

// Windows_5_0_0_beta_21_1580909538 is Windows 5.0.0-beta.21, build 1580909538.
var Windows_5_0_0_beta_21_1580909538 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.21 [Build: 1580909538]",
	Sign:     "bIupsgUpyshmRXuk7BNbdyeVe2kaFeCzK7JYsAC42pTQd2c+BJ9d9k1s++98xUiawk02PJEMHHTOMbSzb0stAQ==",
}

// Linux_5_0_0_beta_21_1580909538 is Linux 5.0.0-beta.21, build 1580909538.
var Linux_5_0_0_beta_21_1580909538 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.21 [Build: 1580909538]",
	Sign:     "pxBYR/tOgH4jlnlRkn3r0KV8QDqMqgwn3laSnX7UlTAiuHsoWC/Ate/h3EJmErG5ZkrPpNfiQ/LwjF5XA716Ag==",
}

// MacOS_5_0_0_beta_21_1580909538 is macOS 5.0.0-beta.21, build 1580909538.
var MacOS_5_0_0_beta_21_1580909538 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.21 [Build: 1580909538]",
	Sign:     "+onDe6gCP47nLw4O6h1YGfW/hcX2obp5lmbIssLC2QI+7ZM5zqlLVfadT/mlGEJQmkPwTbgfB7skWb2RNlSZAw==",
}

// Windows_3_5_0_1581008757 is Windows 3.5.0, build 1581008757.
var Windows_3_5_0_1581008757 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1581008757]",
	Sign:     "qD/zY2WGfK+bWdVtR9diH5Cd4gqNaQoGkyx/CXU9Uj1wcUoa1zl9Q4FyvKknWDUk4xMgW6TwV3/dqEiMCNrHDw==",
}

// Windows_3_5_0_1581019294 is Windows 3.5.0, build 1581019294.
var Windows_3_5_0_1581019294 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1581019294]",
	Sign:     "OefT5cmBEGyvtnycUbFibrYGJ6fbfak/iWy9SkaPtDHs+6XVwuWF8QoPlpPxDVr35Gu0wf7CosU2tKM3cLinCQ==",
}

// Windows_3_5_0_1581183683 is Windows 3.5.0, build 1581183683.
var Windows_3_5_0_1581183683 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1581183683]",
	Sign:     "iRBp5ZpaD2Rl+SBDz0FdDXULs2j/QOM5EQP46DZITMItEkve/XDRx06WeUvMg6F3QQbMGBM+A9XFCPwkrntfCg==",
}

// Windows_3_5_0_1581524851 is Windows 3.5.0, build 1581524851.
var Windows_3_5_0_1581524851 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1581524851]",
	Sign:     "CAufZh4u1fgPkBO9ifw795k5uPG3jzzYZuUJF8ILt0549dOpptY5rPExQlN3DITn8PqYpY7KqmyxbNYGN9QiCw==",
}

// Windows_3_5_0_1581573435 is Windows 3.5.0, build 1581573435.
var Windows_3_5_0_1581573435 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1581573435]",
	Sign:     "xsE0T9FneeP40ZYx0wSCCOp3m+4NPDpDJi6EEl0PL+N3f05rJg62yi3U0x5QUWZ5qTYWqgvg6xK+wxiiU/eXCQ==",
}

// Windows_5_0_0_test_70_1581595773 is Windows 5.0.0-test.70, build 1581595773.
var Windows_5_0_0_test_70_1581595773 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.70 [Build: 1581595773]",
	Sign:     "7hafwSRKQQ9JibQOLqkBY9Xvpcfee6W7G457dYfOAcw+7sVMDESgTZurizhGC48rLUAI5/EmHAHBX1t+0Y29CA==",
}

// MacOS_5_0_0_test_70_1581595773 is macOS 5.0.0-test.70, build 1581595773.
var MacOS_5_0_0_test_70_1581595773 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.70 [Build: 1581595773]",
	Sign:     "nrbngLiQ+oFmVaiep1bqxvtbzhxs9aIV5099xsdzO61dPTMZzkv82QOivGQrrQFyJ9pAPY6NT7MYzUqiNfXeBg==",
}

// Windows_5_0_0_test_71_1581610274 is Windows 5.0.0-test.71, build 1581610274.
var Windows_5_0_0_test_71_1581610274 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.71 [Build: 1581610274]",
	Sign:     "Kx5AAFhCpA18Qpe8omponynjqyY+LJ5YOvLsFx0nyXT4ULXO7wOGj8zOuBnBmEfVdqNxp2D3g8h/+XtpETt1Cg==",
}

// Windows_3_5_0_1581610500 is Windows 3.5.0, build 1581610500.
var Windows_3_5_0_1581610500 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1581610500]",
	Sign:     "YDLAfOb4eRCoIw9rfmwAAi2g7cowAb9UaDebmmRnnMnlgzmPWKEt04pavAHmISYUcUyVcgcN6Xd9TWGXkIp/DQ==",
}

// OSX_3_5_0_1581610500 is OS X 3.5.0, build 1581610500.
var OSX_3_5_0_1581610500 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1581610500]",
	Sign:     "oD3b4mzAO01Rna2kZQR99cacT5ga5wWb5Pbyb/amrmVB8pk9mBhI/lMd3RIZ2FOTIU+Whl+c19L1V6F2F9s6DQ==",
}

// Windows_5_0_0_test_73_1581688728 is Windows 5.0.0-test.73, build 1581688728.
var Windows_5_0_0_test_73_1581688728 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.73 [Build: 1581688728]",
	Sign:     "1kr/E/7znkikhDCNMOPP+e9EI1m5zxKM2UmvPw8myp05FKYYU4jT4qq03eDN9tXXsrVQo21cEaa2iCkx/DpMDQ==",
}

// Windows_3_5_0_1581910955 is Windows 3.5.0, build 1581910955.
var Windows_3_5_0_1581910955 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1581910955]",
	Sign:     "V6WplfyLI3EUNzHpfH3fCsEQPvw+0ZOUjcul6/F7zdM8PH1mYUC/WabyXyZeYSFfkCL6ap8JUTpj/ndIbcLHBg==",
}

// Windows_5_0_0_beta_22_1582011547 is Windows 5.0.0-beta.22, build 1582011547.
var Windows_5_0_0_beta_22_1582011547 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.22 [Build: 1582011547]",
	Sign:     "lzu8BcTXHRlmB5KE+JFk+MvR00HKC+sMojtvZNTT8HF2IAYRQ8RYJTgoMICwVwXmqfnpeVWRm7nlN5aGc1w7Cw==",
}

// Linux_5_0_0_beta_22_1582011547 is Linux 5.0.0-beta.22, build 1582011547.
var Linux_5_0_0_beta_22_1582011547 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.22 [Build: 1582011547]",
	Sign:     "ujCBv4ax/Z1X1/kN5FRcbYx0RdBy910N6HXLMFiGCB/8FkSzn/fVnqGQq5c4j6hI+jxfnXazTVMR4P50G5N9DA==",
}

// MacOS_5_0_0_beta_22_1582011547 is macOS 5.0.0-beta.22, build 1582011547.
var MacOS_5_0_0_beta_22_1582011547 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.22 [Build: 1582011547]",
	Sign:     "O0I6ny9At1k/tCunLjdOyoxmkAh00RkWDg4bMmgQtCgGUa2g9LsMninbuRgq/qEPBpA106to/Br7kCFtU9AiBA==",
}

// Android_3_5_0_1582117478 is Android 3.5.0, build 1582117478.
var Android_3_5_0_1582117478 = ClientVersion{
	Platform: "Android",
	Version:  "3.5.0 [Build: 1582117478]",
	Sign:     "vASJQFPECG2TpUh5ATsR2c/gVrvsuZ9QlMpKN51F+HnanYNH3oCSGoievQX6ACjsKH3OZihNFQZ6f5HRU/MAAg==",
}

// IOS_3_5_1_1582118844 is iOS 3.5.1, build 1582118844.
var IOS_3_5_1_1582118844 = ClientVersion{
	Platform: "iOS",
	Version:  "3.5.1 [Build: 1582118844]",
	Sign:     "3ZiKmiSA9g1xUhb67wgAPz7duV97QCoMQn4OmjqXUffVN5cvztaUhIBm0oZ8n0DEXsgx8hulbqWBFIN8QgAIBA==",
}

// Windows_3_5_0_1582288251 is Windows 3.5.0, build 1582288251.
var Windows_3_5_0_1582288251 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1582288251]",
	Sign:     "TfDGO2PFx40/+aYype6R4NymCpSmaVK5v5H0TPv/RJsQk9Eph9ImMtyScUfxi81Dm1QmUwAzUCYDT7oVp2d2Aw==",
}

// Android_3_5_0_1582632784 is Android 3.5.0, build 1582632784.
var Android_3_5_0_1582632784 = ClientVersion{
	Platform: "Android",
	Version:  "3.5.0 [Build: 1582632784]",
	Sign:     "WdEIgZGcvq/nA72e75D8Lg5XGpzM71uP3ACM9ytu6VOIpnhOvhDOBOEw5+BvdtczwU8mmfSBRp9YOe6weF5MDw==",
}

// Windows_3_5_0_1582634532 is Windows 3.5.0, build 1582634532.
var Windows_3_5_0_1582634532 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1582634532]",
	Sign:     "HIA8YsTxkbsOKakMQQtAwHvEm0fYR1vfpw4W5LJePO2Zi4H7DXPbW88jRS6YpyajE2wBrfDQQ4C1bcyLM4F7CQ==",
}

// Linux_3_5_0_1582634532 is Linux 3.5.0, build 1582634532.
var Linux_3_5_0_1582634532 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1582634532]",
	Sign:     "q+AGeyyc0gKGc0bXXqYuv0Rbnk2OaOyrDZPYSLx6USPv1O2BE4ny6CH+cW4phg7zwQreJan4LwVPL9TXLscyCg==",
}

// OSX_3_5_0_1582634532 is OS X 3.5.0, build 1582634532.
var OSX_3_5_0_1582634532 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1582634532]",
	Sign:     "HVr0/VEWh/5oMXA3nqYsdj8AMEtZs6lcMzTgxVg4vSPzi3WUOzLTgGx6SV3B47qzHdMlndRG+f8ez3VmUBo1Dw==",
}

// Linux_5_0_0_test_79_1582881429 is Linux 5.0.0-test.79, build 1582881429.
var Linux_5_0_0_test_79_1582881429 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-test.79 [Build: 1582881429]",
	Sign:     "v5iYqAuhZ2+dGwUdeVb7SLakgwbTgVyTHGA5aGUbpApvnsb5rGv5R56Oo23TbLJA+I8BG+MUAMPjTAq9bGphDA==",
}

// Windows_5_0_0_beta_23_1583314601 is Windows 5.0.0-beta.23, build 1583314601.
var Windows_5_0_0_beta_23_1583314601 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.23 [Build: 1583314601]",
	Sign:     "aQ38hj+f8Ih+KEy5a9Y+dAS8Pq9lecaVSRlAK+4+3FgTrl4vgooSRYfOsRl9sgP3bDDJ+mmYH/Wp45puckeyDQ==",
}

// Linux_5_0_0_beta_23_1583314601 is Linux 5.0.0-beta.23, build 1583314601.
var Linux_5_0_0_beta_23_1583314601 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.23 [Build: 1583314601]",
	Sign:     "kkzWsdmOEEe4NHmnfH0vZn3Bo0Lixigl/n91SaMpFVUj7sNmjuCnYYHHNC4lXOmk8jqiK2S1HCS9Du2SUhuWDw==",
}

// MacOS_5_0_0_beta_23_1583314601 is macOS 5.0.0-beta.23, build 1583314601.
var MacOS_5_0_0_beta_23_1583314601 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.23 [Build: 1583314601]",
	Sign:     "ylP6xnnn2g0DOvkQE2DgwiDbhm6s1J85SIQRrTgY8JRa5H6FNniAFPgGaxAFmvfianclmn4k7Nm9/McVX1fTCQ==",
}

// Windows_5_0_0_test_87_1583490334 is Windows 5.0.0-test.87, build 1583490334.
var Windows_5_0_0_test_87_1583490334 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.87 [Build: 1583490334]",
	Sign:     "zBVMxaWgifJDMm348f8rKF0fLrnI9w6mXLSDZ4pP183FZafhXqDKKVZcjvaTRv4G4wyt4pFHUaOBwd/ByTh2Aw==",
}

// Linux_5_0_0_test_87_1583490334 is Linux 5.0.0-test.87, build 1583490334.
var Linux_5_0_0_test_87_1583490334 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-test.87 [Build: 1583490334]",
	Sign:     "TdwctqEYENLgcpBtOuCDIZzG1js/u7rsdHS8DkqAEViKsQ27VJTbCvW3Ti0z70mX6g6XZAWixxCeZEf+F81aDg==",
}

// Windows_5_0_0_test_89_1584014675 is Windows 5.0.0-test.89, build 1584014675.
var Windows_5_0_0_test_89_1584014675 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.89 [Build: 1584014675]",
	Sign:     "AWXttmmIF6QzYfwuPgN7YT6+x00iQVE28oAB5kwb2elZ987qJe84FzkJZ6K1zaPBLeYn3VBqsCW+OdMg2CNHBQ==",
}

// Windows_3_5_0_1584088288 is Windows 3.5.0, build 1584088288.
var Windows_3_5_0_1584088288 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1584088288]",
	Sign:     "yghoziODwuQ3LBpgUUHT2/kCTx6Ygbju2WxzM8bojYGGiuQrL/+Tb2XKETUhYJWfHZ8WH2PvIvB4MFZIcJO5Dg==",
}

// Linux_3_5_0_1584088288 is Linux 3.5.0, build 1584088288.
var Linux_3_5_0_1584088288 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1584088288]",
	Sign:     "9UVeO3R3xm1taUmEFTnngy0C1iQovwzWy1HwyFlIbBDDQaN9SHR0hK2GpNrdquliY0wtNSbAJ/7BtGhk3or9CQ==",
}

// OSX_3_5_0_1584088288 is OS X 3.5.0, build 1584088288.
var OSX_3_5_0_1584088288 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1584088288]",
	Sign:     "wdYDalZQtOO0+HQAtq8xwMiWSS2bqXUltbyIGBWebrU8YWTFuIeqmhA9W/jo4W4yj6251qRLvxnFaO1SywptCQ==",
}

// Windows_5_0_0_beta_24_1584452452 is Windows 5.0.0-beta.24, build 1584452452.
var Windows_5_0_0_beta_24_1584452452 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.24 [Build: 1584452452]",
	Sign:     "iLM0f1OmaoBrg6IqLW0GlSJcR6kydwtJjlblwIbMmbzIXa2xzwXbtREgvq5eenK8VfBfckg2g/KZygGV2XOHBQ==",
}

// Windows_3_5_0_1584525989 is Windows 3.5.0, build 1584525989.
var Windows_3_5_0_1584525989 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1584525989]",
	Sign:     "boQPV7FO3e0PJIxh1gSAG8Z3/NxLWbzVej7glvkQaSfvPWj3Bg385Ikn33wLHn6brcWHAo+fpdQdZskXFmj8Dg==",
}

// OSX_3_5_0_1584525989 is OS X 3.5.0, build 1584525989.
var OSX_3_5_0_1584525989 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1584525989]",
	Sign:     "nX5cpDbTPvbzSivBfvqWGpjokX42n+1HlIKxmHBTBPhLbIl2Fn1f7znSY/31K3fj1hJPJVOyuOKyPsRHK/uXBw==",
}

// Windows_3_5_0_1584610661 is Windows 3.5.0, build 1584610661.
var Windows_3_5_0_1584610661 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.0 [Build: 1584610661]",
	Sign:     "8um3guYdjDlKHOUZMYqt//4nT9k+SBYnAAP/9CarVp5pUXEzYaTZlflyOi6hjYIDn5cQ7gdvrKmdXLOXBJiqCA==",
}

// Linux_3_5_0_1584610661 is Linux 3.5.0, build 1584610661.
var Linux_3_5_0_1584610661 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.0 [Build: 1584610661]",
	Sign:     "kHfR/JyZ6Ah06rW/t+dFIHkOgLGFth5CCbRr9T3xfPd2gqL5CeYei47LGBjA9K9GrVVRivF0L5eo5MrxGh/QDA==",
}

// OSX_3_5_0_1584610661 is OS X 3.5.0, build 1584610661.
var OSX_3_5_0_1584610661 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.0 [Build: 1584610661]",
	Sign:     "RZJrT/fysauFMv9ugB82ZAZN/t/MSWeJmFLu35FXx/r+3O1QZrM8rDfU5Iq/moG68hPRcc12KloOvrlVTdfiBg==",
}

// Windows_5_0_0_beta_24_1584621089 is Windows 5.0.0-beta.24, build 1584621089.
var Windows_5_0_0_beta_24_1584621089 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.24 [Build: 1584621089]",
	Sign:     "unVP5b7fNc0ZDXsA54GknvLR/FWIQM/obpQKGDUdTBJU44fOUk8p2Nq3o3HtcS44nwhA8Njxi6x2lsuOs8jwDA==",
}

// Linux_5_0_0_beta_24_1584621089 is Linux 5.0.0-beta.24, build 1584621089.
var Linux_5_0_0_beta_24_1584621089 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.24 [Build: 1584621089]",
	Sign:     "iTRafOxViAWbIg4Uc2je7KrxkNTdc8WjEtQvceCAsvPY/wL1tgd21Sy19iqASdAOJeQ302Kb06ajsq+8SdfhCA==",
}

// MacOS_5_0_0_beta_24_1584621089 is macOS 5.0.0-beta.24, build 1584621089.
var MacOS_5_0_0_beta_24_1584621089 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.24 [Build: 1584621089]",
	Sign:     "eD5rtvlqnZOBDLN/2VKKh/DeNsPJMY/H1y5yn53MuFKJJDR8VKwnuTRXLHPShzgCEQrjo4EvoY5ksMFRpeAwAw==",
}

// Windows_3_5_1_1584725003 is Windows 3.5.1, build 1584725003.
var Windows_3_5_1_1584725003 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.1 [Build: 1584725003]",
	Sign:     "EPmzKEUtMuD+7bg4eEzU4sJTRI0wRB6kQx2T5GqCyQB+kgBZO96plC4uNcZUBtwSXYYbkNkyfQc9ZwgOp2CUDQ==",
}

// Windows_3_5_1_1584726885 is Windows 3.5.1, build 1584726885.
var Windows_3_5_1_1584726885 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.1 [Build: 1584726885]",
	Sign:     "B19O3onHeCV8mc5mBqLP5PGof4VdvwLI8HFhxKsXRsDWOu04xbpJjkCy5RYTjMstCSo/Dkhl/WX0puT5/PEyAw==",
}

// Windows_3_5_1_1584955996 is Windows 3.5.1, build 1584955996.
var Windows_3_5_1_1584955996 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.1 [Build: 1584955996]",
	Sign:     "LY20d0yqDFwknHND8FYADnvsKnq81kya6lAEnJEQ+87oN0k8KqTXMDpy/0z0yC54+B8Mo/P8kSjrpRugaVAPDA==",
}

// Linux_3_5_1_1584955996 is Linux 3.5.1, build 1584955996.
var Linux_3_5_1_1584955996 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.1 [Build: 1584955996]",
	Sign:     "YtR6uJ0zzFwlAXoV1ikV8DVD9y7ka0WCh46wvALArdCBw9zaBLE7ese6Uu3U2Dmg4//ook5cNvupeOlzHcGPDQ==",
}

// OSX_3_5_1_1584955996 is OS X 3.5.1, build 1584955996.
var OSX_3_5_1_1584955996 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.1 [Build: 1584955996]",
	Sign:     "xk8NdgtqWPihDy1gUPGVtcLkfrl5Fd2lfigB0N7d9K0VGyCxC4ZvQOdX6kM/StTX1xulCnENp0wb+gqwjO5nBA==",
}

// Windows_5_0_0_test_95_1585049319 is Windows 5.0.0-test.95, build 1585049319.
var Windows_5_0_0_test_95_1585049319 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.95 [Build: 1585049319]",
	Sign:     "zhiNFDElBjkQIL6xELBUPjVIbYbECvby4qqq+8xo5r2RhF6ZfjebvmX2iqtEJsEyRoNqekcvAH7KGDUdzFaLAg==",
}

// Windows_5_0_0_test_96_1585156359 is Windows 5.0.0-test.96, build 1585156359.
var Windows_5_0_0_test_96_1585156359 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.96 [Build: 1585156359]",
	Sign:     "w9C5vLHnbUcg7sypEF/GbrqiMnabQ/i1Xazcsc3fjF1STvHWHuBuRT2vBAXcGLIpqxQMz8J4l8yDqgBFzFs+Dg==",
}

// Windows_3_5_2_1585741147 is Windows 3.5.2, build 1585741147.
var Windows_3_5_2_1585741147 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.2 [Build: 1585741147]",
	Sign:     "If7v4eV0QZjeSpH2ld/suq6dW08v0UZDRRTjDy0d/4mg+Ve+sENwGtggDZYPLgDj/3FEJLVuKZmBw0v1LUM7DQ==",
}

// Linux_3_5_2_1585741147 is Linux 3.5.2, build 1585741147.
var Linux_3_5_2_1585741147 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.2 [Build: 1585741147]",
	Sign:     "qILhBdVwjtE8enMjQL02b9i80CRybJgolFQWfQgLPjWLvgbNMeqAAFS+X7HB7FuF5VKq82biDYK2cuQJjTAbCw==",
}

// Windows_5_0_0_test_100_1585752032 is Windows 5.0.0-test.100, build 1585752032.
var Windows_5_0_0_test_100_1585752032 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.100 [Build: 1585752032]",
	Sign:     "VxWe1xx5ggANpg9NbR9NAG8Kn0KyJII7IphKVXElGKgVnCdHPSwINF+mnZl/l3e2P+EBvvLzTXK1I0wfbu+iDQ==",
}

// Windows_3_5_2_1585812952 is Windows 3.5.2, build 1585812952.
var Windows_3_5_2_1585812952 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.2 [Build: 1585812952]",
	Sign:     "6HIIG9j6bIUavbDFJR50Hk3hwl1j4BL/1hQS5Q4JfAS0oerwLNBbdAfXM963aOlE8yan9d/LWiXnuSKhQXAKAQ==",
}

// Linux_3_5_2_1585812952 is Linux 3.5.2, build 1585812952.
var Linux_3_5_2_1585812952 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.2 [Build: 1585812952]",
	Sign:     "Fy5GNeXUzrP5chKDWhG4G7T3jj8tjg0JkoTNRl+tgrONOWNbNf1zBD+I2LNqJREJXvaSrXcMB1pOQQrWKIXqDQ==",
}

// OSX_3_5_2_1585812952 is OS X 3.5.2, build 1585812952.
var OSX_3_5_2_1585812952 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.2 [Build: 1585812952]",
	Sign:     "VhEA3HpeSCbV06Dfh5wonQ+XMuC8dG96ZXvU5HCNLvkSatAfOsDGLaQNLfbkVZVcs0Hvf9oPFgWvAseSX96rCw==",
}

// Windows_5_0_0_manage_permissions_8_1585925917 is Windows 5.0.0-manage-permissions-8, build 1585925917.
var Windows_5_0_0_manage_permissions_8_1585925917 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-manage-permissions-8 [Build: 1585925917]",
	Sign:     "NOVj4XEgHGfIgYhqXcryyaIOId/yVGGUqbJrWZ1tXSMog/lhiiuXZ0ULOibABIXD/QH08x1dln99AiZM/dLyDA==",
}

// Windows_5_0_0_network_monitor_1_1586167450 is Windows 5.0.0-network-monitor-1, build 1586167450.
var Windows_5_0_0_network_monitor_1_1586167450 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-network-monitor-1 [Build: 1586167450]",
	Sign:     "LxpaUacQltAK5yxM++Vx3PJPtL0uC9YH9Qspyt3TQxUh0zBzmwIjRaNP3w+aNtyzN6JChinARB5b+LsPLim2CA==",
}

// Windows_3_5_3_1586172156 is Windows 3.5.3, build 1586172156.
var Windows_3_5_3_1586172156 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1586172156]",
	Sign:     "ujcLD9+x4JxR89dkHBEOf8ZxzX2yZjUNBu8mh5f9arIuNOBSbrrG3eRjG0qFNbQnRIUh058tSfes5TRyaF+kBg==",
}

// Linux_3_5_3_1586172156 is Linux 3.5.3, build 1586172156.
var Linux_3_5_3_1586172156 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.3 [Build: 1586172156]",
	Sign:     "GRdePYP+MJpGf6wtKmB2CEMZJ2x1wJLIX81CKqr9mVUDWyp8LTBzOJYxaldUboH+UGh2LOByHNR5EpHA3gdNCw==",
}

// OSX_3_5_3_1586172156 is OS X 3.5.3, build 1586172156.
var OSX_3_5_3_1586172156 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.3 [Build: 1586172156]",
	Sign:     "8+NprKwynOC+wGqVZnaYc5g2A31f9MdoChKK3RYKd19lZEVRZngk5FFB1lIyI9TQKdNC4opfhGL3dvu9bAtEDw==",
}

// Windows_5_0_0_test_104_1586348340 is Windows 5.0.0-test.104, build 1586348340.
var Windows_5_0_0_test_104_1586348340 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.104 [Build: 1586348340]",
	Sign:     "h/lwYRBPj+GeQZqUNyXOOvVfWlue4rr9FfGgHt7vMlPWCddPH2fNjDf9K7dNGoXMm5DDdVHUfPgcKfC6+nBWBw==",
}

// MacOS_5_0_0_test_104_1586348340 is macOS 5.0.0-test.104, build 1586348340.
var MacOS_5_0_0_test_104_1586348340 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.104 [Build: 1586348340]",
	Sign:     "O29jwgoTOWgTnZYjhQobrMh607sddxbOlesu8xBU1oMtm74mLZ65dajvMJPb20jpsXhdCqk+KHt8TcMvNx5fDQ==",
}

// Windows_3_5_3_1586353391 is Windows 3.5.3, build 1586353391.
var Windows_3_5_3_1586353391 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1586353391]",
	Sign:     "knmVmUvvQTTfOUCWlQncjWFWHXFqZMntUbIPIi/YLcxdW4iP3woJQgVTaIZPEiluMT5A7tb2lSk/r+Byh5R6Dw==",
}

// Windows_3_5_3_1586853103 is Windows 3.5.3, build 1586853103.
var Windows_3_5_3_1586853103 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1586853103]",
	Sign:     "Ht2CRGb39a+QZ8YlnbfA8Ip8pQa9kRd2A8Nmj8veYiGMV4K0TaP7UG2bwuxxJC7sIdre1esb2mHric8ZD4hqDQ==",
}

// Windows_3_5_3_1586955962 is Windows 3.5.3, build 1586955962.
var Windows_3_5_3_1586955962 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1586955962]",
	Sign:     "lnyUR4m/DQIpXkhOTqjrpH6zIxjo/gHgjoiQb4zDEuI039Ys+K3ST/fZV2n4u6/rJmV6fYgmoEKQ2OBjh9ULDA==",
}

// Linux_3_5_3_1586955962 is Linux 3.5.3, build 1586955962.
var Linux_3_5_3_1586955962 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.3 [Build: 1586955962]",
	Sign:     "WxwBpvlHwS5fmiEn1S7ATpPU1oR8U/tdSzpZvAfoIOv78w+oL9UlTouDquVwrl6L0IXIZvRIDs+32EfbIZVmCg==",
}

// OSX_3_5_3_1586955962 is OS X 3.5.3, build 1586955962.
var OSX_3_5_3_1586955962 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.3 [Build: 1586955962]",
	Sign:     "/9gsbyyJoyHW1okwykGgXrn2j29wvnEfnw6/Hvft2WS12CURxTv5L9uLuu36I5u3TzWOxyB9dEbD1FeZ201uCQ==",
}

// MacOS_5_0_0_test_106_1587037548 is macOS 5.0.0-test.106, build 1587037548.
var MacOS_5_0_0_test_106_1587037548 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.106 [Build: 1587037548]",
	Sign:     "pb3fpCZJylNXmOsJcVMo5laRCtKWHrCBeUNGGCehZb76PC593skEWD4N6UmEAyPwoi6Fg6C7/cmbaWP4rtSpAg==",
}

// Windows_3_5_3_1587566168 is Windows 3.5.3, build 1587566168.
var Windows_3_5_3_1587566168 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1587566168]",
	Sign:     "k+/YQOZz+AlZt6h9/XFgHDI49rx2ce/Ngewj4pvGpFUmI1c/4bP0bAeeK9Q7P1JIzzdwp4qh0CkaSDbVYLjDCw==",
}

// Linux_3_5_3_1587566168 is Linux 3.5.3, build 1587566168.
var Linux_3_5_3_1587566168 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.3 [Build: 1587566168]",
	Sign:     "v5Qg6ng2ILr9Ca6iTgjfYnShBDwioRf6fyA6iODHsNUhutwq7yXoU8z64NJRGNuqLKVbS95Fpm7Npu3YAfm7Cw==",
}

// Windows_5_0_0_test_111_1587633723 is Windows 5.0.0-test.111, build 1587633723.
var Windows_5_0_0_test_111_1587633723 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.111 [Build: 1587633723]",
	Sign:     "60DETVUkR9veo0Cc9WCV+t3r0w836CfRZTgw/sZH0LL6AwtAab8sbcYNcOBybSssn+QgZI37kdc7B9YViszgCw==",
}

// Windows_3_5_3_1587971024 is Windows 3.5.3, build 1587971024.
var Windows_3_5_3_1587971024 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1587971024]",
	Sign:     "Kvmj7qX6wJCPI5GVT71samfmhz/bvs7M+OTXWB/JWxdQbxDe17xda7dzUWLX7pjvdJTqZmbse1HBmTxThPKvAg==",
}

// Linux_3_5_3_1587971024 is Linux 3.5.3, build 1587971024.
var Linux_3_5_3_1587971024 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.3 [Build: 1587971024]",
	Sign:     "59chu1YQ1W4DdVj+yJOVmwhJK7s9p9FatqIjQRxEDmIb0CcDDO/K8CrbVnBHbD67/cExJbC3PjC/o/n0pDbiCg==",
}

// Windows_5_0_0_beta_25_1588064367 is Windows 5.0.0-beta.25, build 1588064367.
var Windows_5_0_0_beta_25_1588064367 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta.25 [Build: 1588064367]",
	Sign:     "VnoQXCs1i1iEe7miGKqxKkxkjFAPIryo5cSf+eBLBmiBMOnJjrsICg+HxHEHcOdUL4Hu7VfP+8F4tYrN2TmxBg==",
}

// Linux_5_0_0_beta_25_1588064367 is Linux 5.0.0-beta.25, build 1588064367.
var Linux_5_0_0_beta_25_1588064367 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta.25 [Build: 1588064367]",
	Sign:     "L5rpK9OLT84Hgpg/NXSCwpHfrRc/JTtMa/kFfaD2rlF7c/YHiEnly/4+A9y0iowA70+5JEzyH6CBjkniiz4DAw==",
}

// MacOS_5_0_0_beta_25_1588064367 is macOS 5.0.0-beta.25, build 1588064367.
var MacOS_5_0_0_beta_25_1588064367 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta.25 [Build: 1588064367]",
	Sign:     "+Y1iB58sLO38/4AI1YRUlEhXhhrbkAVbaSmOcZj0IrTmQm1eY+prEYJPQgF8StFdjWmAGmMG3ezzb0wEzRE3CQ==",
}

// Windows_5_0_0_test_113_1588173300 is Windows 5.0.0-test.113, build 1588173300.
var Windows_5_0_0_test_113_1588173300 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.113 [Build: 1588173300]",
	Sign:     "hTPLObkRW1TRRym4E6fJC7P9ngYa5IuFwe75RJSdu0Cju76VHNIBKzLBrU59IgmD3MChY5sEiCBML3V7IM1RCA==",
}

// Windows_3_5_3_1588250739 is Windows 3.5.3, build 1588250739.
var Windows_3_5_3_1588250739 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1588250739]",
	Sign:     "arEooa/3dcP6Ck10yN65zk8z/Lt7QnxgApOi+IoPafYFKo0b0QeZ48qT3Kmtu2VseU9YI7JQrfpfvOF3YZrvBA==",
}

// Windows_3_5_3_1588261372 is Windows 3.5.3, build 1588261372.
var Windows_3_5_3_1588261372 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1588261372]",
	Sign:     "MwZT29nmkJekgubjZGJV08bDegfP5Y481bThFRBna0UDhECDEfLcdW/0BE6YTC7aCvbcx5EZMXE/R+jdRUnhAA==",
}

// Windows_5_0_0_test_114_1588589210 is Windows 5.0.0-test.114, build 1588589210.
var Windows_5_0_0_test_114_1588589210 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.114 [Build: 1588589210]",
	Sign:     "P3dUXUfUWuT5TXGcCP53CEQLJkAfiJQDH/ojNxyyrLnfbNUR1bX+Dr9tirPYjuOIMF4iVvNXTYiSHRO5ENs4Ag==",
}

// Linux_5_0_0_test_114_1588589210 is Linux 5.0.0-test.114, build 1588589210.
var Linux_5_0_0_test_114_1588589210 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-test.114 [Build: 1588589210]",
	Sign:     "YEEYWLVRGDSB/SfAgUEl5K8J8kZ6m+PkgLW3L3R0pxAmRhttvM6Db/Fxc1CjE0ShWMcIQmxb8qlDTTOxxew0Aw==",
}

// MacOS_5_0_0_test_114_1588589210 is macOS 5.0.0-test.114, build 1588589210.
var MacOS_5_0_0_test_114_1588589210 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test.114 [Build: 1588589210]",
	Sign:     "pNeLWGmMtRvfHj4GrfOZP4c1yjustIsh2rjddFWDaIZX2n5cO1ivnK5jzDkjX1hANUMlPTrIZReLIYi5k3L+DQ==",
}

// Windows_3_5_3_1588756070 is Windows 3.5.3, build 1588756070.
var Windows_3_5_3_1588756070 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.3 [Build: 1588756070]",
	Sign:     "WY2De4HPPvwdiO6ZglSXQ3zq6HkeL0ZQ7GjZSMXN2X77p9KDBxE1O5QdSTQjrXfl5RUkEA7hcgjWfTxOcI5mCA==",
}

// Linux_3_5_3_1588756070 is Linux 3.5.3, build 1588756070.
var Linux_3_5_3_1588756070 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.3 [Build: 1588756070]",
	Sign:     "bWiXMVa4E++lbV6zpRywdvKilqfi1++nTZd1NbPnMUfQfVW0JNk5U5a2vkGft8Dd21RNDHKBt8t77G/PAEA7Cg==",
}

// OSX_3_5_3_1588756070 is OS X 3.5.3, build 1588756070.
var OSX_3_5_3_1588756070 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.3 [Build: 1588756070]",
	Sign:     "/Z0BeU58BQwf80NuLOC7q5lUUcscztBUVePMpKSsUxumpJJQX34NsGw4N0DMekVEg9Ds8RQJk+xMopD+fsY0DQ==",
}

// Windows_5_0_0_test_116_1590740393 is Windows 5.0.0-test.116, build 1590740393.
var Windows_5_0_0_test_116_1590740393 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.116 [Build: 1590740393]",
	Sign:     "70tCpJiGP2b5zKIt6HzTREBqE0njaUyWj/dCVd+DUT/QvhB8j8coh7BZ+rEWzS0bco4uBWJBCPFY7RGekwh0Dw==",
}

// Windows_5_0_0_test_120_1592228855 is Windows 5.0.0-test.120, build 1592228855.
var Windows_5_0_0_test_120_1592228855 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-test.120 [Build: 1592228855]",
	Sign:     "UJaqz8lXzZrmF7/nWZF0aMUcJQYyDluinAxDKxZNxSMeTLWUShnBHIXs7EL8yqjikqTTdwsMzEvNAZ1CsMGqBw==",
}

// Windows_3_5_5_1594109255 is Windows 3.5.5, build 1594109255.
var Windows_3_5_5_1594109255 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.5 [Build: 1594109255]",
	Sign:     "RP85L3nZRJe1EmD2uN2ujwqoqnOudzh6mCvpvNxn3vqokKQ/RImt53JpaVfDQANdXRM3iiCy5K9ilILdbDScDg==",
}

// Linux_3_5_5_1594109255 is Linux 3.5.5, build 1594109255.
var Linux_3_5_5_1594109255 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.5 [Build: 1594109255]",
	Sign:     "AG3H2BCe5B2B8gQoYBhLymU2iUaaVth0hnUMk6tHK2Wa/q6Y5KEktbHEJxRE84LGttm7kzZbvNzFx1SIbdXhAQ==",
}

// OSX_3_5_5_1594109255 is OS X 3.5.5, build 1594109255.
var OSX_3_5_5_1594109255 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.5 [Build: 1594109255]",
	Sign:     "6pAN4KDU74hkqHQyJmaLnQZbxK9tPAKfoocmHFYggF20dCIsrc6yKGkaKN6OoSC0BGaOpg6d/JDCus9IZg2fAg==",
}

// Windows_3_5_5_1594213121 is Windows 3.5.5, build 1594213121.
var Windows_3_5_5_1594213121 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.5 [Build: 1594213121]",
	Sign:     "fL4Bx3UDyN/wgrzE3fgwayKnvMhg3SWcQRzJdt3eKno3rM3rlcVujk7yeki1Gs1xh12uJC+kK0lyGjxCea0CCA==",
}

// Linux_3_5_5_1594213121 is Linux 3.5.5, build 1594213121.
var Linux_3_5_5_1594213121 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.5 [Build: 1594213121]",
	Sign:     "qcElldtu07fZwpqJibMXCuGjdzgk1W+bHOmtrMRQzUEo+qxkETaR/dUpUqrF3WUKQ0XC58E0wG584toQGk2jBA==",
}

// OSX_3_5_5_1594213121 is OS X 3.5.5, build 1594213121.
var OSX_3_5_5_1594213121 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.5 [Build: 1594213121]",
	Sign:     "WYv9XAEAMJXYm56+9YiSEufC7iUFimD9AIgPqXBbjfYqu7VHw6btHiWl67r6Obric2J9E+fBihAH4AUCllD5BA==",
}

// MacOS_5_0_0_ui_polishing_2_1596738566 is macOS 5.0.0-ui-polishing-2, build 1596738566.
var MacOS_5_0_0_ui_polishing_2_1596738566 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-ui-polishing-2 [Build: 1596738566]",
	Sign:     "Era2fdPOli6XWa1zj5mAjO7caaeQZsnOIe3KVowly4P3Pv8NDASk0+vw3j+Hy/7jkyaFDj+zRbEB72MKDNPhBg==",
}

// Windows_5_0_0_tschat_test_7_1597217264 is Windows 5.0.0-tschat-test-7, build 1597217264.
var Windows_5_0_0_tschat_test_7_1597217264 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-tschat-test-7 [Build: 1597217264]",
	Sign:     "A7kIbQ8i2LYwB5cIjO+fwkrJFXo5LPa8dPj31bL4CxoCSh3VBoL8KV7cKAKgi3zMGbIdQ44j/XaAmsFy/nVkDQ==",
}

// Windows_5_0_0_tschat_test_9_1597240212 is Windows 5.0.0-tschat-test-9, build 1597240212.
var Windows_5_0_0_tschat_test_9_1597240212 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-tschat-test-9 [Build: 1597240212]",
	Sign:     "+kSSDzRWNgs7s6RDmpJA1UoNk0Vvd28KjVQ+DP/6U3elwMx6DC8TF2XjEuV5TXjB7ti52lm0aZonL/y5mdrNBQ==",
}

// Windows_5_0_0_ui_polishing_4_1597390040 is Windows 5.0.0-ui-polishing-4, build 1597390040.
var Windows_5_0_0_ui_polishing_4_1597390040 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ui-polishing-4 [Build: 1597390040]",
	Sign:     "617fWVNMxefDPrTGXNzjkMMAy0PBSxMJzlOGUdOc1CyEFWJfRlaPYKykozgskjDtOR4J76EGURz86IBMxVq8Bg==",
}

// MacOS_5_0_0_ui_polishing_4_1597390040 is macOS 5.0.0-ui-polishing-4, build 1597390040.
var MacOS_5_0_0_ui_polishing_4_1597390040 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-ui-polishing-4 [Build: 1597390040]",
	Sign:     "SP70Ec4DgG3EgDsSTQ+aWxKRTpr1ECxJoS7GENe9Xrc6hHnOKoqTHxPZ5vOgd4JwvNL71cUbPZhUHx1jHyn1Cw==",
}

// Windows_5_0_0_flag_test_3_1597393952 is Windows 5.0.0-flag-test-3, build 1597393952.
var Windows_5_0_0_flag_test_3_1597393952 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-flag-test-3 [Build: 1597393952]",
	Sign:     "brM47NqjZLKE2MdYGPtf0D730zbenP5m0xhnG3100CXkguPX/a1lJjTS7wpyRmfoHqJn/840nMlUmusH+K9RCQ==",
}

// Windows_5_0_0_move_testing_1_1597499112 is Windows 5.0.0-move-testing-1, build 1597499112.
var Windows_5_0_0_move_testing_1_1597499112 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-move-testing-1 [Build: 1597499112]",
	Sign:     "WVLzzHFy/sN6kvXEtrv4zw+qyUMQSLNt8k2pFt1GvO0kOqZEq08u3wDCy1G8O/3mdIIrMNYAUQpIijMAOpwUDA==",
}

// Windows_5_0_0_move_testing_2_1597522136 is Windows 5.0.0-move-testing-2, build 1597522136.
var Windows_5_0_0_move_testing_2_1597522136 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-move-testing-2 [Build: 1597522136]",
	Sign:     "ULSMPYrWPPcxhmdxdnQvxRFvYAZXKR/BveIN0brlQ0Z40bTusc9sxkq3eeuZB67dIefF5xpCmXQiF1rpdKVLDw==",
}

// Windows_5_0_0_move_testing_4_1597581653 is Windows 5.0.0-move-testing-4, build 1597581653.
var Windows_5_0_0_move_testing_4_1597581653 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-move-testing-4 [Build: 1597581653]",
	Sign:     "YSpkYU2/uYwzDWmXdXQjgtj8uk3ko/ZQJhZU0NVXyj7yar0pm7g8NaWIQusd0fVQxlkRdhvt8FNqNpcZFvnPBA==",
}

// Windows_5_0_0_flag_test_4_1597915096 is Windows 5.0.0-flag-test-4, build 1597915096.
var Windows_5_0_0_flag_test_4_1597915096 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-flag-test-4 [Build: 1597915096]",
	Sign:     "CXeiOEZDQrd5Xmwl6zNlkmcyPw2SydkrcvUvc42fVqc7KZN46G9CZQJ6AlDv6N38xRd+Ugqnxvgtt6R7pDtEBQ==",
}

// Windows_5_0_0_move_testing_7_1597931781 is Windows 5.0.0-move-testing-7, build 1597931781.
var Windows_5_0_0_move_testing_7_1597931781 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-move-testing-7 [Build: 1597931781]",
	Sign:     "4bUyAdFhGoaaGdKjaiaKnHG/1S+6piduMJgqvAAzWOhHstEZbqUOLJqfENyN9bNgoZhJ+5rQV30FxzIay4jJBg==",
}

// Windows_5_0_0_tschat_test_11_1598016546 is Windows 5.0.0-tschat-test-11, build 1598016546.
var Windows_5_0_0_tschat_test_11_1598016546 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-tschat-test-11 [Build: 1598016546]",
	Sign:     "uSqM3SaZZFMQ+wu5WMDO1bsSVS8UO0RiK0ClQQqxGTa3/wSYId1nNeFo6uNEPfbbMMRddfplzGoquRAshCWhDw==",
}

// Windows_5_0_0_ui_polishing_5_1598262399 is Windows 5.0.0-ui-polishing-5, build 1598262399.
var Windows_5_0_0_ui_polishing_5_1598262399 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ui-polishing-5 [Build: 1598262399]",
	Sign:     "ovnKt/9eEjZWmF9MEMmLchAQ+Dlror+Dnz4ULrYU7FmjpVZZgjj+U4qXzdeGkHnMSIq5NsNj+IPQwBCHfcKBAA==",
}

// Windows_5_0_0_ui_polishing_6_1598444718 is Windows 5.0.0-ui-polishing-6, build 1598444718.
var Windows_5_0_0_ui_polishing_6_1598444718 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ui-polishing-6 [Build: 1598444718]",
	Sign:     "R/P/PtSOH7fiN7jcQV4ynXlWQ+mu5dszFutDCPxSbX94KiQDOyuKNRx6wbGIFCbKUbFsqfSWtQpdNLXSdxA5Bg==",
}

// Windows_5_0_0_ui_polishing_7_1598531141 is Windows 5.0.0-ui-polishing-7, build 1598531141.
var Windows_5_0_0_ui_polishing_7_1598531141 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ui-polishing-7 [Build: 1598531141]",
	Sign:     "6EtepyA9GZo4oopLY4/eGNsXkBtcIRYFBd9eL7jBvefO/aWmpWUqPLUsXTdfxxiuDLqaAxUpjFFH6ys8UToACA==",
}

// Windows_5_0_0_4f3ac28d8_1598636763 is Windows 5.0.0-4f3ac28d8, build 1598636763.
var Windows_5_0_0_4f3ac28d8_1598636763 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-4f3ac28d8 [Build: 1598636763]",
	Sign:     "ipbprZW/Wj+awfG+YTkQ7qoWkxCTk08wGrKhUUKindDZ8KA+0qKyfnChOgUPrpu4SoQQbArw8hLpBiFpclbnBw==",
}

// Windows_5_0_0_tschat_test_15_1599059062 is Windows 5.0.0-tschat-test-15, build 1599059062.
var Windows_5_0_0_tschat_test_15_1599059062 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-tschat-test-15 [Build: 1599059062]",
	Sign:     "0omqloYB4FSc7j0jknZ2VPEWSbqfTtriAT1RaP+FSaI7tnG6CAqG5+1ZAw1ngPtaithbqHx5taLBU5Gi1Q1CCg==",
}

// Windows_5_0_0_cobra_test_2_1599165810 is Windows 5.0.0-cobra-test-2, build 1599165810.
var Windows_5_0_0_cobra_test_2_1599165810 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-2 [Build: 1599165810]",
	Sign:     "U7nvm2ZCxB9dwSGyKt4TlVPDoBXYVfCamV9uyilR5CcHKXIExtFkH2W86HUKJtMnYtWnb5sZ3PePT0LqzEO2Cw==",
}

// Windows_5_0_0_alpha400_1599165997 is Windows 5.0.0-alpha400, build 1599165997.
var Windows_5_0_0_alpha400_1599165997 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha400 [Build: 1599165997]",
	Sign:     "vAzgabsbFnHs5ceGGJw8y65cb/0Aua4dei3iOP/dJ18H6jVhfEhAaX9K3x6iEgBbJQVZ9DM9CJ7TbGXAmdP3BQ==",
}

// Windows_5_0_0_alpha401_1599486917 is Windows 5.0.0-alpha401, build 1599486917.
var Windows_5_0_0_alpha401_1599486917 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha401 [Build: 1599486917]",
	Sign:     "mFkz+RiCfiBWzElK/xhVd9N6mlsAzu80fTVxqYTZWNky3lF424z2FY5w+AjpwJdQXJaO4476CNMZdCiKeciEAA==",
}

// Windows_5_0_0_alpha402_1599557851 is Windows 5.0.0-alpha402, build 1599557851.
var Windows_5_0_0_alpha402_1599557851 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha402 [Build: 1599557851]",
	Sign:     "QBcatWqkPlr7DSTr8UGNPd3UnyaC3H5Tqf05fpMgsqX8LwFrlmH/nkVoNFDolAQEzvlvSbPTAlOfkeLxqTPVCg==",
}

// Windows_5_0_0_alpha403_1599578655 is Windows 5.0.0-alpha403, build 1599578655.
var Windows_5_0_0_alpha403_1599578655 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha403 [Build: 1599578655]",
	Sign:     "Wd2+dE49zR+vcFRcOavZ31cVGBTpI0/PIVI6umJT4g5p1yRjG2Y1DqCY51TEyFMTdL3Ki82TKxz0TfRilNR1Dg==",
}

// Windows_5_0_0_alpha404_1599669220 is Windows 5.0.0-alpha404, build 1599669220.
var Windows_5_0_0_alpha404_1599669220 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha404 [Build: 1599669220]",
	Sign:     "CMsTD2jD9+Xs5S2gKNX7vtHMO0GpbiiiAyL3MGzpe5N0KlLpUw2L2G2hB3gGD5YpfKG4WYn19ehfo2+eJMm7CA==",
}

// Android_3_5_0_1599755905 is Android 3.5.0, build 1599755905.
var Android_3_5_0_1599755905 = ClientVersion{
	Platform: "Android",
	Version:  "3.5.0 [Build: 1599755905]",
	Sign:     "uxDkYjha2wFI0YQqFbresfwTKfUftLNUI/nNxHfBo6TqlACwDMKfGrtwNmzVUwR0Rpv9OhOOvJ/AwyeCY2LUDg==",
}

// Windows_5_0_0_cobra_test_3_1599769084 is Windows 5.0.0-cobra-test-3, build 1599769084.
var Windows_5_0_0_cobra_test_3_1599769084 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-3 [Build: 1599769084]",
	Sign:     "JpEr6MBZnRsh71PkO8VNi0X7w1ABPt8utVPSOyyn+tRa+q6AVI0i2dSblnfTsgBnN9DEYd0yNUVItXkzxOTLCw==",
}

// Windows_5_0_0_54c87064a_1599843538 is Windows 5.0.0-54c87064a, build 1599843538.
var Windows_5_0_0_54c87064a_1599843538 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-54c87064a [Build: 1599843538]",
	Sign:     "Oadma4PaBgy+bwN4i9HTq1TlK/+597K79TC2vLjx+HRAvqmH8lOt2dpTM7FRzZXvSZZD2U7tpJPDtQ8FSsnKDA==",
}

// Windows_5_0_0_alpha406_1599846284 is Windows 5.0.0-alpha406, build 1599846284.
var Windows_5_0_0_alpha406_1599846284 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha406 [Build: 1599846284]",
	Sign:     "8YQ2CFzDErBCL/4EAbJkbTH4yb22vET9ZZ8f4b1I9NrPyKJLLVPmiJhqeayqJaHMaxRmjUV0SliI22PcgcdsBg==",
}

// Windows_5_0_0_cobra_test_4_1599917420 is Windows 5.0.0-cobra-test-4, build 1599917420.
var Windows_5_0_0_cobra_test_4_1599917420 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-4 [Build: 1599917420]",
	Sign:     "qyUPfMweT9jCmjq7+nOy92VShZ2nuIZKHPWcZ7e3x6nqhT1bQSWDNdvj+mIOfn2qMsUh0wScnSASHBetwe2IDw==",
}

// Windows_5_0_0_alpha407_1600159955 is Windows 5.0.0-alpha407, build 1600159955.
var Windows_5_0_0_alpha407_1600159955 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha407 [Build: 1600159955]",
	Sign:     "MvvOPDyWEHaDiNQVvFqUC7b9xT7IypfBF1CCUQgYycJSHBTXieGB2vIo0vWfB29Ng4teXvUf73VyyywP+YSsBA==",
}

// Windows_5_0_0_alpha408_1600254224 is Windows 5.0.0-alpha408, build 1600254224.
var Windows_5_0_0_alpha408_1600254224 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha408 [Build: 1600254224]",
	Sign:     "zU8VYYXa6Nj2zuI5cNsX4lu6sN7FlzOhFCNB+q+KUtVplKNnQnTuNIw6qykGj757kie9/UsXpxIqiCqZONNSCQ==",
}

// Windows_5_0_0_updater_test_8_1600284324 is Windows 5.0.0-updater-test-8, build 1600284324.
var Windows_5_0_0_updater_test_8_1600284324 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-updater-test-8 [Build: 1600284324]",
	Sign:     "cCCPTceQ2GqeV1MdPsF+HJjteOhK6sy837lQzoxLHYi92IaChxpsANQCGGJmpMPA8FfPRujMqUO2wxPdNRVhAA==",
}

// Windows_5_0_0_alpha409_1600339559 is Windows 5.0.0-alpha409, build 1600339559.
var Windows_5_0_0_alpha409_1600339559 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha409 [Build: 1600339559]",
	Sign:     "KVyePfU2z8XNWWIl/iFGHIWthdaTWZGC2qouCghpPr99uhQ1P2zqXalwJXwDE8mFhGP1/K3KiB4P+RM+MdxrDA==",
}

// Windows_5_0_0_alpha410_1600365598 is Windows 5.0.0-alpha410, build 1600365598.
var Windows_5_0_0_alpha410_1600365598 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha410 [Build: 1600365598]",
	Sign:     "qN94hYAUzrC4037xTz8PKgs+YUpn/tcvMH08WvSOmZIXHC7wNrYZYZvHZ8uBmrUZe7YJfhrWgLxWxYZDfot2Dw==",
}

// Android_3_5_0_1600439598 is Android 3.5.0, build 1600439598.
var Android_3_5_0_1600439598 = ClientVersion{
	Platform: "Android",
	Version:  "3.5.0 [Build: 1600439598]",
	Sign:     "V5VxAFG1qIozePu/NwA7GC6Lkv/qcNR5sSQf2luqnwra1LmahG1B8HxSd43WHHS68bXLY0lepDjX6by1i5JICQ==",
}

// Windows_5_0_0_alpha411_1600469361 is Windows 5.0.0-alpha411, build 1600469361.
var Windows_5_0_0_alpha411_1600469361 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha411 [Build: 1600469361]",
	Sign:     "YioE63QY3Xo62SeFh9+y9YDqdBUacYEk2AHNbJiznOt0QfFgGaXKs4+OiZF4QHB0dkY8tnK0u18JQbFMti43Ag==",
}

// MacOS_5_0_0_alpha411_1600469361 is macOS 5.0.0-alpha411, build 1600469361.
var MacOS_5_0_0_alpha411_1600469361 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-alpha411 [Build: 1600469361]",
	Sign:     "Hufdiya9ezgpPW+tv5I8w00Scx3BbSYFBVBV5VL8z/Wyj0LrSE4y+na5XLmS2JUUl4cMVuEnimhzE7V0opqYAw==",
}

// Windows_5_0_0_alpha412_1600599064 is Windows 5.0.0-alpha412, build 1600599064.
var Windows_5_0_0_alpha412_1600599064 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha412 [Build: 1600599064]",
	Sign:     "7T7c8XivXygpk+TFtLXIGcBaLzr0+ut/RlOBY3/r+ymNJ4fMXr1jwNZWm0LTUnoRfl11dLwJFIQ1THYz5X7xCw==",
}

// Windows_5_0_0_beta26_rc1_1600686231 is Windows 5.0.0-beta26-rc1, build 1600686231.
var Windows_5_0_0_beta26_rc1_1600686231 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc1 [Build: 1600686231]",
	Sign:     "xuSjmrIAg0QFnqNa1h+93d3Z2pK1U1ZwZeR9G9obHsGFnDvw8a+JHGUDDyUew5rTSP391wyE+jaFoF9yEoCzBg==",
}

// MacOS_5_0_0_beta26_rc1_1600686231 is macOS 5.0.0-beta26-rc1, build 1600686231.
var MacOS_5_0_0_beta26_rc1_1600686231 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta26-rc1 [Build: 1600686231]",
	Sign:     "l5WNBZhy1XSkDaIjTEqWexk4rWFND4krcMr7miKW2n4cCzuDO297wiD+JitHQ4WlrrH56ba2iYzXEQ7XCJExAw==",
}

// Windows_5_0_0_beta26_rc2_1600787359 is Windows 5.0.0-beta26-rc2, build 1600787359.
var Windows_5_0_0_beta26_rc2_1600787359 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc2 [Build: 1600787359]",
	Sign:     "ryvuIgSkD9wxkyGgviy6IKWiUCkTWXYt1EB9BGmtb7cO9wbg/YMgmhLFyxjHBc/T27GA963bTo8YPeN1fW6hDA==",
}

// Windows_5_0_0_beta26_rc3_1600861922 is Windows 5.0.0-beta26-rc3, build 1600861922.
var Windows_5_0_0_beta26_rc3_1600861922 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc3 [Build: 1600861922]",
	Sign:     "dcReQuakK5hux2rvz032Ol4Xg/32ErtopQG9Ue05z+Br4o6EkWou3SOFXLs7+wEQODFCdWMwyHULG10ja/UpDg==",
}

// Windows_5_0_0_beta26_rc4_1600948191 is Windows 5.0.0-beta26-rc4, build 1600948191.
var Windows_5_0_0_beta26_rc4_1600948191 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc4 [Build: 1600948191]",
	Sign:     "T1o1pShuaBXz0ikD5yxHG85ZlScEp3yq+QZh7VbpvOwWRtsjvKfaQQ3wZNNzXEzvxHBrHdrxDQXwnoLKSpKlAw==",
}

// MacOS_5_0_0_beta26_rc4_1600948191 is macOS 5.0.0-beta26-rc4, build 1600948191.
var MacOS_5_0_0_beta26_rc4_1600948191 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta26-rc4 [Build: 1600948191]",
	Sign:     "t3c1xpHIuySi89cBf6fQyatdpFsjy3FByJR2wAabHXXHdavLTAUWKDEHgypRBV7USjYAXaxyQKy+gJZBc623Cg==",
}

// Windows_5_0_0_beta26_rc5_1601022865 is Windows 5.0.0-beta26-rc5, build 1601022865.
var Windows_5_0_0_beta26_rc5_1601022865 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc5 [Build: 1601022865]",
	Sign:     "xC/f1gV4UFzN1zRwSHmn5kYhRcJ9XJIdR32QlhNaf/GhM4uk2WOxo+AaFXpfVN8Zjf+YepOpecVTbajUF6m+CA==",
}

// MacOS_5_0_0_beta26_rc5_1601022865 is macOS 5.0.0-beta26-rc5, build 1601022865.
var MacOS_5_0_0_beta26_rc5_1601022865 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta26-rc5 [Build: 1601022865]",
	Sign:     "016WaAPU1cQq5tcgppr8UJLISyhRraHRcIBt1Zt5ivD0JTS2E5bnFeJ1599+5hAYtBZaR3r+CyBxdd2kbrjPDA==",
}

// Windows_5_0_0_beta26_rc6_1601285793 is Windows 5.0.0-beta26-rc6, build 1601285793.
var Windows_5_0_0_beta26_rc6_1601285793 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc6 [Build: 1601285793]",
	Sign:     "VK6yvfCpPk2VbqU0MStyWK7OKbGWqFy1ckLGTYZ2+pbpJAhuPRnFhEAfy9SOoN2McczquLt0CNzi2dt8MSkTCw==",
}

// MacOS_5_0_0_beta26_rc6_1601285793 is macOS 5.0.0-beta26-rc6, build 1601285793.
var MacOS_5_0_0_beta26_rc6_1601285793 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta26-rc6 [Build: 1601285793]",
	Sign:     "kO9K2RgUzoU339T315xm6N/hdEM+4fyX0bfUWogr5y1SL9F6gE2mfFpuZUJjlc8DxUR93hZ6nq6gzjZCHhCcDw==",
}

// Windows_5_0_0_beta26_rc7_1601384917 is Windows 5.0.0-beta26-rc7, build 1601384917.
var Windows_5_0_0_beta26_rc7_1601384917 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc7 [Build: 1601384917]",
	Sign:     "7VKnNQeltTiOk09y8EORDrgcg2JhANV76y2bO8lt+RgOK91OVTBQcFtV7+Ph+mFPnVsWeeMdZqDHPihUX5NrAA==",
}

// Windows_5_0_0_beta26_rc8_1601393829 is Windows 5.0.0-beta26-rc8, build 1601393829.
var Windows_5_0_0_beta26_rc8_1601393829 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26-rc8 [Build: 1601393829]",
	Sign:     "T/Iwhz5+9ADH+uG4bTaSdFJtTpaEjQXt9c4SQRKR7sTOvLmOMMcI/aecv2zots5sUrb0loVA/6XKfVpOaDmCDw==",
}

// Windows_5_0_0_beta26_1601452077 is Windows 5.0.0-beta26, build 1601452077.
var Windows_5_0_0_beta26_1601452077 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26 [Build: 1601452077]",
	Sign:     "5Ky3eRSCxlef+IKraGDsCDGOuwVS79IReK3g0z8s2H+E/v+KRaw/l+cXjyBqGDUrLQAGmG5UmHbIiuAhz6ZFDA==",
}

// Windows_5_0_0_beta26_1601476259 is Windows 5.0.0-beta26, build 1601476259.
var Windows_5_0_0_beta26_1601476259 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta26 [Build: 1601476259]",
	Sign:     "bgzGTN3/lKVdabzBu+fMaaeETaZtRiM7Iou/juKI13o5dY4inVOsPXDmO5flq2/sQ9HicCIHBZO+aReIu+FnBA==",
}

// Linux_5_0_0_beta26_1601476259 is Linux 5.0.0-beta26, build 1601476259.
var Linux_5_0_0_beta26_1601476259 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta26 [Build: 1601476259]",
	Sign:     "8JoozxphOv+RXiaqutCgokpg1+ObD1+7+JvOsPA5aeVU9eQAxYtWKIcZm6QvbFkMkcJY5HQ6V3loP3+m0TMWCA==",
}

// MacOS_5_0_0_beta26_1601476259 is macOS 5.0.0-beta26, build 1601476259.
var MacOS_5_0_0_beta26_1601476259 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta26 [Build: 1601476259]",
	Sign:     "YwqNu9i1wmtlS2GNUE+wRHnzLXNFB8rUx/ZYhWm7PDBnzEbqMrZA/6n9Sh9/zQ5mbc67b6Ms+CY/N+T6jJYLAw==",
}

// Windows_5_0_0_cobra_test_5_1601543268 is Windows 5.0.0-cobra-test-5, build 1601543268.
var Windows_5_0_0_cobra_test_5_1601543268 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-5 [Build: 1601543268]",
	Sign:     "duCYmWU/OHzBDFMNDjEKLNfrvf4sltic0IhpsrDPHoqzuNkY1Xko36ZfQfDvbUHRFXYVVYR3thQILuCwEFr1DA==",
}

// Windows_5_0_0_cobra_test_6_1601558370 is Windows 5.0.0-cobra-test-6, build 1601558370.
var Windows_5_0_0_cobra_test_6_1601558370 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-6 [Build: 1601558370]",
	Sign:     "XsbQghGaprnZaMF6snKzGXBChAq25KOllmkjlN9WDFPJEhaJdt0f4wsWVBOQ9KFIhkE6d0+Ie6tS0XVqxcifCA==",
}

// Windows_5_0_0_beta27_rc1_1601630484 is Windows 5.0.0-beta27-rc1, build 1601630484.
var Windows_5_0_0_beta27_rc1_1601630484 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta27-rc1 [Build: 1601630484]",
	Sign:     "sQY12C5m0GDUhxXMsAH88dyt+pwZglSRq2hsHTzlh6CCHFFh2jMBWzolmZX2LCi2Y3sIkZZDWdeGAQ7a1rftBg==",
}

// MacOS_5_0_0_beta27_rc1_1601630484 is macOS 5.0.0-beta27-rc1, build 1601630484.
var MacOS_5_0_0_beta27_rc1_1601630484 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta27-rc1 [Build: 1601630484]",
	Sign:     "Loaqp/e/iy/3qRRdqTPdT/MFGjiQhzPqCkzOmdYcoMVoRt3dwv/Vi/ipaCpHNaSPKg0aIS7LdQoFGfputapUBg==",
}

// Windows_5_0_0_beta27_rc2_1601922246 is Windows 5.0.0-beta27-rc2, build 1601922246.
var Windows_5_0_0_beta27_rc2_1601922246 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta27-rc2 [Build: 1601922246]",
	Sign:     "XJjYehJ/lhThfRD8UIe+4zMQy1LEAtFY3qf1rcOYtSW0aExaM2gpLVVsoEUz+vGrkabk/zSiCF0dfw/owtsjAA==",
}

// Windows_5_0_0_beta27_rc3_1601985868 is Windows 5.0.0-beta27-rc3, build 1601985868.
var Windows_5_0_0_beta27_rc3_1601985868 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta27-rc3 [Build: 1601985868]",
	Sign:     "81lDEQYZk4t4Rmw6Lm9pQVXQvXFY87viiM6cNxHr1VfQi567R7a9oEpLGi4aNs5tN56k8jwajo7SnHoasW1XAQ==",
}

// Windows_5_0_0_beta27_1601995137 is Windows 5.0.0-beta27, build 1601995137.
var Windows_5_0_0_beta27_1601995137 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta27 [Build: 1601995137]",
	Sign:     "AGF1tTgjMDW8/1R0NiTg3kTrEJ26NIY/HAmrBIotBjCePmFtemvEge/Ap8LqLblmnfnYwuNbF2QDlornXstsBg==",
}

// Linux_5_0_0_beta27_1601995137 is Linux 5.0.0-beta27, build 1601995137.
var Linux_5_0_0_beta27_1601995137 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta27 [Build: 1601995137]",
	Sign:     "R0dzSefvqoYfC5BBia6KL4A0SWbQk2/JVTsJjgtf0nD9fID593Myv34/oyObKr3MI9dyggNGiLJBGucK3UcPDA==",
}

// MacOS_5_0_0_beta27_1601995137 is macOS 5.0.0-beta27, build 1601995137.
var MacOS_5_0_0_beta27_1601995137 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta27 [Build: 1601995137]",
	Sign:     "DcfxKwqnole3TzHXGi/vgXJ+HSlN6v5SqpQfcKW7RqPft1UC20Om1Iyt97rREgE8VWpkvgOTfCjO0wM3O6j5DA==",
}

// Windows_5_0_0_cobra_test_7_1602056579 is Windows 5.0.0-cobra-test-7, build 1602056579.
var Windows_5_0_0_cobra_test_7_1602056579 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-7 [Build: 1602056579]",
	Sign:     "P3Qln4qvk5GsbwBxNd/rQeLFwJwPX6TnvRX4tx2OrjpZjse1LiymkUa0rJamE4OigA0VNUo5YqhWoFyowMrBDw==",
}

// Windows_5_0_0_cobra_test_10_1602071823 is Windows 5.0.0-cobra-test-10, build 1602071823.
var Windows_5_0_0_cobra_test_10_1602071823 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-10 [Build: 1602071823]",
	Sign:     "4IReei/v9/1ZQ9LTNrZbRQBig1ybEy9oPZ0sgvcNjHyRU5oTlm8W1sH+gPb6X7TBaAlGTVwbxnzWeHj8nbxHDA==",
}

// Windows_5_0_0_cobra_test_11_1602168387 is Windows 5.0.0-cobra-test-11, build 1602168387.
var Windows_5_0_0_cobra_test_11_1602168387 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-test-11 [Build: 1602168387]",
	Sign:     "14jQJo21vyK+wwLoAVe0s6HE+K8j/8gBUevO9yF/1byplcQKS/xwD1jakNCM7rJs8iLSo75vTkdTF1pQWJocCw==",
}

// Windows_5_0_0_beta28_rc1_1602250328 is Windows 5.0.0-beta28-rc1, build 1602250328.
var Windows_5_0_0_beta28_rc1_1602250328 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta28-rc1 [Build: 1602250328]",
	Sign:     "8oW09UjVpXnQCDGBLJtyz3LzKQj69wPqBfHCCkGSkWcFOp3zqYrDQttOFjd7628rq8SczY9oiSJ85K3VwHPUDQ==",
}

// MacOS_5_0_0_beta28_rc1_1602250328 is macOS 5.0.0-beta28-rc1, build 1602250328.
var MacOS_5_0_0_beta28_rc1_1602250328 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta28-rc1 [Build: 1602250328]",
	Sign:     "An+eZ5ePOnilhs44F9Z0uGHGTFr5q7GaUkN2I1Xv2lPXbmRJS2ePiuLo7M7wAybymRwm/+eEB3bT/NVwCJQWBw==",
}

// Android_3_5_0_1602492685 is Android 3.5.0, build 1602492685.
var Android_3_5_0_1602492685 = ClientVersion{
	Platform: "Android",
	Version:  "3.5.0 [Build: 1602492685]",
	Sign:     "lKoOgVcaAsMGEpVjJi181o3H37beWguSR5efJmIJMsMZ/n8Vf2QKxpV+gALOJKgFlciZDL+e3VOd81uyhuizDg==",
}

// Windows_5_0_0_beta28_rc2_1602580552 is Windows 5.0.0-beta28-rc2, build 1602580552.
var Windows_5_0_0_beta28_rc2_1602580552 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta28-rc2 [Build: 1602580552]",
	Sign:     "Fvk4Xr/Z+HXAlO2MhB4dRN7Wi7X6IxwXSlXH8SFSkwxiPAnBKcNwvS1RonjilpxXNRwqhGemahkGewJAMtzfDg==",
}

// MacOS_5_0_0_beta28_rc2_1602580552 is macOS 5.0.0-beta28-rc2, build 1602580552.
var MacOS_5_0_0_beta28_rc2_1602580552 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta28-rc2 [Build: 1602580552]",
	Sign:     "oIEegsz45Eqs3RDI8jC5wdEu25TsrliV6c1gMaJraLRjvaU2p17xOmXzG5dtL6Qx81OGDqRF82ooXXE6jgymCw==",
}

// Windows_5_0_0_beta28_1602660382 is Windows 5.0.0-beta28, build 1602660382.
var Windows_5_0_0_beta28_1602660382 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta28 [Build: 1602660382]",
	Sign:     "pQ0ZCYZovulw3eqwdvzJpq/2d8XwqcTnRLggziiDmRn+FxeOtkWmemhlRZbgljo/GFV2n1Xj4T0Z5ktgMKXRBA==",
}

// Linux_5_0_0_beta28_1602660382 is Linux 5.0.0-beta28, build 1602660382.
var Linux_5_0_0_beta28_1602660382 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta28 [Build: 1602660382]",
	Sign:     "cBBzfORlQ7Hgo+bIysxOjBrMn8R8C/cz7HefCctDZeqW/9jtQgdmC4j0WG2z44zFkSQpKyn37g/I14C7cg+YDg==",
}

// MacOS_5_0_0_beta28_1602660382 is macOS 5.0.0-beta28, build 1602660382.
var MacOS_5_0_0_beta28_1602660382 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta28 [Build: 1602660382]",
	Sign:     "wNdxosl+2z6YkNmd4jaLwWHQiuPDE+9NvGqN9Y/edJ3530ktACUE9/KbtDhLIhdk6Fgx+SwxKhuusqxszCOmBQ==",
}

// Windows_5_0_0_beta29_rc1_1602672104 is Windows 5.0.0-beta29-rc1, build 1602672104.
var Windows_5_0_0_beta29_rc1_1602672104 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta29-rc1 [Build: 1602672104]",
	Sign:     "dU9SLOX6O8CnwmohtUrViexxDa40NeIoW5TWshyd0vuB4y/vyP69MRxcW7ma1Z4B9GgOO6MJo44M5FL6FvOyCw==",
}

// MacOS_5_0_0_beta29_rc2_1602840532 is macOS 5.0.0-beta29-rc2, build 1602840532.
var MacOS_5_0_0_beta29_rc2_1602840532 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta29-rc2 [Build: 1602840532]",
	Sign:     "kHx3QjHof8thbn4Y6us8PdWEcs5+V7LnakvBLWvZEGUkOg16xUuYWuoFYs6bYBVKTVgoO74+XY3/KT4SPBK0DA==",
}

// Windows_5_0_0_beta29_rc3_1603115757 is Windows 5.0.0-beta29-rc3, build 1603115757.
var Windows_5_0_0_beta29_rc3_1603115757 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta29-rc3 [Build: 1603115757]",
	Sign:     "/EBNwj3g8b4OHFSGkFRpCffr8AeWBXV5qGzviB/EVqGvBR4f8nCF4onxGVsf/Iezl6BtoqJ0OcNAU9FHGTU2Aw==",
}

// Windows_5_0_0_beta29_1603199536 is Windows 5.0.0-beta29, build 1603199536.
var Windows_5_0_0_beta29_1603199536 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta29 [Build: 1603199536]",
	Sign:     "szczHLDI5WYcdftBao1SMIrCeCt8Z54Rfiw3Vc+X1veNGKKo+V4gQ8WR0h4pOmve3Jp4J1lAk/zIhY1GHtPCBQ==",
}

// MacOS_5_0_0_beta29_1603199536 is macOS 5.0.0-beta29, build 1603199536.
var MacOS_5_0_0_beta29_1603199536 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta29 [Build: 1603199536]",
	Sign:     "EZtK0haoikiJyxO3NQyLEvJLPiL3V8hRgD4jrKLzsbwGSbrlzQMjA/7k3gPaRi5GN6QJgavKi/XJ0bFu0PVKAQ==",
}

// Windows_5_0_0_beta29_1_1603277784 is Windows 5.0.0-beta29.1, build 1603277784.
var Windows_5_0_0_beta29_1_1603277784 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta29.1 [Build: 1603277784]",
	Sign:     "OIPofb7scMCORX6+SsAk6T1ndB/GtUE1V/XnnwqdqFiVjXHPVHCfYnFG163sHCbkYxy+DQapPQzNCpink/RSDw==",
}

// Linux_5_0_0_beta29_1_1603277784 is Linux 5.0.0-beta29.1, build 1603277784.
var Linux_5_0_0_beta29_1_1603277784 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta29.1 [Build: 1603277784]",
	Sign:     "+W6wJ0uz+9pg36eWCM/dgcDfjiYBnvfd3befRzTCpMBBhXABn2p5biGB+xGBllaR8q0CkMOV2oPCORWrfPfQCg==",
}

// MacOS_5_0_0_beta29_1_1603277784 is macOS 5.0.0-beta29.1, build 1603277784.
var MacOS_5_0_0_beta29_1_1603277784 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta29.1 [Build: 1603277784]",
	Sign:     "aIAisThgSbFhvGL9QxDWs3C8e3AcfhG6pd/9V/5VGw6sO4aEf51962byGzxFoidCYG+yz37I/MuX/P/FrSUvCQ==",
}

// Windows_5_0_0_beta30_rc1_1603375915 is Windows 5.0.0-beta30-rc1, build 1603375915.
var Windows_5_0_0_beta30_rc1_1603375915 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta30-rc1 [Build: 1603375915]",
	Sign:     "nwz6Oy9f9Z9xao1rNhcXbFn9mprcW4GFmtEDrUArG70HRjAHUgbH0nxVyJqCQ2n5JgY0MAG4h6sEyFdtFNc5Bg==",
}

// MacOS_5_0_0_beta30_rc1_1603375915 is macOS 5.0.0-beta30-rc1, build 1603375915.
var MacOS_5_0_0_beta30_rc1_1603375915 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta30-rc1 [Build: 1603375915]",
	Sign:     "VMzjKVxPX7C3LgziUDO+3cguPTvuTowhPXNbHBN3ktMUkPeyPN61dAY/keUxNzSB2RoQzp4LMYOxT5cdGUlkBw==",
}

// Windows_5_0_0_beta30_rc2_1603714412 is Windows 5.0.0-beta30-rc2, build 1603714412.
var Windows_5_0_0_beta30_rc2_1603714412 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta30-rc2 [Build: 1603714412]",
	Sign:     "S2M4cvuUFJS5qOCIzn+IC93bmrc8l8E3PxElaIGS8g9VU2ScNs9xB3gt3SCF1u3lFFJvc7zXt/ZeA09f0ao5CA==",
}

// Windows_5_0_0_beta30_rc3_1603793389 is Windows 5.0.0-beta30-rc3, build 1603793389.
var Windows_5_0_0_beta30_rc3_1603793389 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta30-rc3 [Build: 1603793389]",
	Sign:     "bgsEUyHjvTl55ve+tV3/FhWEyDBtyQimszKh4KZoLD8dTWkx5nAPkoqB6FZP51W98Zg0m6IItHXBMy+hAguTDg==",
}

// Windows_5_0_0_beta30_1603882166 is Windows 5.0.0-beta30, build 1603882166.
var Windows_5_0_0_beta30_1603882166 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta30 [Build: 1603882166]",
	Sign:     "Sk7MrmeeytvFmIHJXrtYCTnPnXNXM+OYQdz/OsKvW+m6UQuqiEqWutvnGH+d7eO6ewOSD2AO+dyN177THrm9Cg==",
}

// Linux_5_0_0_beta30_1603882166 is Linux 5.0.0-beta30, build 1603882166.
var Linux_5_0_0_beta30_1603882166 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta30 [Build: 1603882166]",
	Sign:     "d4pjtaDVETsz9zK2Yf/19Dj8gKurV9YkPVe1gk+6sQS/E5IwgZN0WcwEGmMj7lHOqWCyLsgtvMe4h82i0u/QAA==",
}

// MacOS_5_0_0_beta30_1603882166 is macOS 5.0.0-beta30, build 1603882166.
var MacOS_5_0_0_beta30_1603882166 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta30 [Build: 1603882166]",
	Sign:     "yPfkHfZ9LAXdHnFfc96rdLFkveU9tjZkRr+X6PLIBuQcWPS5kX0CfJRrL0vPNJm4Z3hrbFk8MLRoDWkZf4RNCw==",
}

// Windows_5_0_0_internal_1_1603899622 is Windows 5.0.0-internal-1, build 1603899622.
var Windows_5_0_0_internal_1_1603899622 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-internal-1 [Build: 1603899622]",
	Sign:     "fTvi3sI024I7nRiOJnrJFF0VH2YMHkcs+c0yAXbLsBOinkIj+yVus7NjK7MuZh6kr21T5ekpCRqSvYLntZ4tAA==",
}

// Windows_3_5_5_1604062410 is Windows 3.5.5, build 1604062410.
var Windows_3_5_5_1604062410 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.5 [Build: 1604062410]",
	Sign:     "YE7gG8tUil7L7o0kk4EO6yvPARRG3TNwTcQFQLm6kKBCbfiC5u7OYJR0sy3r2kkFiCF9GbLggJccicACEi6pDQ==",
}

// Windows_5_0_0_beta31_rc1_1604069291 is Windows 5.0.0-beta31-rc1, build 1604069291.
var Windows_5_0_0_beta31_rc1_1604069291 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta31-rc1 [Build: 1604069291]",
	Sign:     "XUUFhBoCvBRmwkQ77W2K/gZ4oOO3ofea0r5Xi6/3A4Dn9dlTQfrhc0GeEBu4FgLeH6jggfe7UnW306ONqHUvDg==",
}

// Windows_5_0_0_beta31_rc2_1604331167 is Windows 5.0.0-beta31-rc2, build 1604331167.
var Windows_5_0_0_beta31_rc2_1604331167 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta31-rc2 [Build: 1604331167]",
	Sign:     "nZ0rkauM6FZIV7k9Q/hTHA8H1234uLKgtbPBJteBJ6cCqUhP0vtqXfB8wN3t71LlHlxHI4wWvrNVlkBRRJN5Aw==",
}

// Windows_5_0_0_beta31_1604481627 is Windows 5.0.0-beta31, build 1604481627.
var Windows_5_0_0_beta31_1604481627 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta31 [Build: 1604481627]",
	Sign:     "UrzzT7VDY5k55hPwaRZ1MmAA1xWWEqBWr3EqpEHxg4qtmJM1Mw9Q4mmR41pAiRHV4BHMvn9l6YePT3BZrBBlBQ==",
}

// Linux_5_0_0_beta31_1604481627 is Linux 5.0.0-beta31, build 1604481627.
var Linux_5_0_0_beta31_1604481627 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta31 [Build: 1604481627]",
	Sign:     "UdQzwtuA/9YF986x9YoKhCYQML5E35Xt6/bnXHI20CNa7Y9k5W7bl4WJBXUKbe91BmdaO798dp4nLgawHyZWBg==",
}

// MacOS_5_0_0_beta31_1604481627 is macOS 5.0.0-beta31, build 1604481627.
var MacOS_5_0_0_beta31_1604481627 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta31 [Build: 1604481627]",
	Sign:     "76JLTz1/BXuV6aHKQhCVOGooXviJMoDsy3r6LUwjEbQb83P2RvF0taKke22V8N5cx4+gVj2a/sIdVMbRshG3Bw==",
}

// Windows_3_5_5_1604483867 is Windows 3.5.5, build 1604483867.
var Windows_3_5_5_1604483867 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.5 [Build: 1604483867]",
	Sign:     "5pvFQlWp8tKMVQ/rQNuAQPc1ujNyl41gsC1utJy0gxhQ+0XjNRgJnYu0C2lAhzEc8feXxG42Q+YDargxtdM7AQ==",
}

// Linux_3_5_5_1604483867 is Linux 3.5.5, build 1604483867.
var Linux_3_5_5_1604483867 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.5 [Build: 1604483867]",
	Sign:     "JJFd41bido/K1U6JfzKQ+XOopaFiJDjJwub6tuHv+4ibyCyNzYlB7pKqGHUEmBoAg/hR+mqHhn1d1LQfeIF7DQ==",
}

// OSX_3_5_5_1604483867 is OS X 3.5.5, build 1604483867.
var OSX_3_5_5_1604483867 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.5 [Build: 1604483867]",
	Sign:     "ZexDMFulps0EgC6eLh3yf+Z3hDWR/u1H1HyaLhBA5FM01fdsFxfB1QgnSc5N+KSzsOE5ErchWQLipTjTg9AEAw==",
}

// Windows_5_0_0_beta32_rc1_1604501880 is Windows 5.0.0-beta32-rc1, build 1604501880.
var Windows_5_0_0_beta32_rc1_1604501880 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta32-rc1 [Build: 1604501880]",
	Sign:     "aeAVy42rf0tsg29Kl9jYejxwA1g2K2SV34LCqN0ILtp3VJnYKYhkKkE8a3CI3x3EhXn5TqwwxKyIf4aDTIEXAg==",
}

// Windows_5_0_0_beta32_rc2_1604657081 is Windows 5.0.0-beta32-rc2, build 1604657081.
var Windows_5_0_0_beta32_rc2_1604657081 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta32-rc2 [Build: 1604657081]",
	Sign:     "qPVigZMZdpv4SRprBWwJ2o8djXiinFr/d5oUgQ1iy/mQZUzr6D8JTUuyJ8yV1r9+vVcSkKKe3O2Yg4RiguGnBA==",
}

// MacOS_5_0_0_beta32_rc2_1604657081 is macOS 5.0.0-beta32-rc2, build 1604657081.
var MacOS_5_0_0_beta32_rc2_1604657081 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta32-rc2 [Build: 1604657081]",
	Sign:     "45+foTPJrbahtZiNO7Gr8P5f8ZwJdeu/5Dj54Poley4H+cSnpyEvdbbs/g6vuhJOaI0FbUcC2KPnjK1tQmkICA==",
}

// MacOS_5_0_0_beta32_rc3_1604936365 is macOS 5.0.0-beta32-rc3, build 1604936365.
var MacOS_5_0_0_beta32_rc3_1604936365 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta32-rc3 [Build: 1604936365]",
	Sign:     "7i5hLTypUCCR4sGhIrkZfQ5yJfLBYdbKm3JkDtqXq7l2677XssCmMx0fqzKcSX5j3KR36CKnLHcZ5yH0c4AwDw==",
}

// Windows_5_0_0_beta32_rc4_1605002654 is Windows 5.0.0-beta32-rc4, build 1605002654.
var Windows_5_0_0_beta32_rc4_1605002654 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta32-rc4 [Build: 1605002654]",
	Sign:     "/Ik/dAPEPC0D99aOGNDYvG/REbwmcYBlLXcFSZwHq2V3DXDzeNUOr43gHlL1AzMiYd2x0rZrCcXrn3fLYMd9AA==",
}

// Windows_5_0_0_beta32_rc5_1605018568 is Windows 5.0.0-beta32-rc5, build 1605018568.
var Windows_5_0_0_beta32_rc5_1605018568 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta32-rc5 [Build: 1605018568]",
	Sign:     "kBeUGR/3y5FDIp9HwvM7RpDI72GTgiFLdDELhjJ34IOPL3OKNvLEez9MB4uiRRoh7jYIuZZQwdwY3OYuBB5CAg==",
}

// Windows_5_0_0_beta32_1605097383 is Windows 5.0.0-beta32, build 1605097383.
var Windows_5_0_0_beta32_1605097383 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta32 [Build: 1605097383]",
	Sign:     "+Hzkhe5qVBsBkNGbDtqrGJheXxXTkjLEZP1lxO2yYbXf8XI4jsVrt9+Iy4EPAgQOgl48HnHpQE2/Ek/3BI5WAg==",
}

// Linux_5_0_0_beta32_1605097383 is Linux 5.0.0-beta32, build 1605097383.
var Linux_5_0_0_beta32_1605097383 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta32 [Build: 1605097383]",
	Sign:     "GoVvALlg86eqEfMeOwZ7TAYNH5O+UrsuB45tVZD0NbJ4m45Z9XApYnA0SPDX/gdgxUTw7WqsWUdQr50zDJMZAg==",
}

// MacOS_5_0_0_beta32_1605097383 is macOS 5.0.0-beta32, build 1605097383.
var MacOS_5_0_0_beta32_1605097383 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta32 [Build: 1605097383]",
	Sign:     "h2c24ww5+HNInt+CzeNvGWWtxAKPSiUTFKvGKJGlviPtP+lvxzUsqTKvuBtOBDhcG+TM9kuxUY2U/7RUcWYWDw==",
}

// Windows_5_0_0_bab0e5e53_1605109329 is Windows 5.0.0-bab0e5e53, build 1605109329.
var Windows_5_0_0_bab0e5e53_1605109329 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-bab0e5e53 [Build: 1605109329]",
	Sign:     "+XLUGbX5E5bx0V7yrsD1DuyYm4se96DEXF/5uL6uJNkW1lw6ddglRR19c7MvvbR3uFi09RzQVXEKUb0IvNP5Dg==",
}

// IOS_3_5_6_1605182235 is iOS 3.5.6, build 1605182235.
var IOS_3_5_6_1605182235 = ClientVersion{
	Platform: "iOS",
	Version:  "3.5.6 [Build: 1605182235]",
	Sign:     "7hXO+2TSz+nHL30cI30zI5XlpZqjowOcsaaGWY0CkpAK/IdAheS1QW5EKUuvwLPQZ5SRoZirpM+EX25NgsnnAA==",
}

// Windows_5_0_0_cobra_testing_11_1605194844 is Windows 5.0.0-cobra-testing-11, build 1605194844.
var Windows_5_0_0_cobra_testing_11_1605194844 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-11 [Build: 1605194844]",
	Sign:     "VzJPVfF+dN9/FshBgVmptx1nRSxXITOGH5KrTpjBSNn6IX+EMBx7Sczgz/8+fi4hqv39CwGvfeaYnI3cPCsuBw==",
}

// Windows_5_0_0_beta33_rc1_1605268533 is Windows 5.0.0-beta33-rc1, build 1605268533.
var Windows_5_0_0_beta33_rc1_1605268533 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta33-rc1 [Build: 1605268533]",
	Sign:     "RAQ5R5NtgheSxed32RtPvVGP+g7a3yqkrYWeDwrR3KthQMErlvdXy6tpOixlLtMH/lC6DrHrfLXz1+6esbe0DA==",
}

// MacOS_5_0_0_beta33_rc1_1605268533 is macOS 5.0.0-beta33-rc1, build 1605268533.
var MacOS_5_0_0_beta33_rc1_1605268533 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta33-rc1 [Build: 1605268533]",
	Sign:     "91JFloed7+rI+CgAwk9F85W0dsi3T0HfoF/nuEHrfsD34Rajyv4xNg3zDM1l/KEjEkg/2YCHnZ7Ht53X1pizAA==",
}

// MacOS_5_0_0_test_icons_1605393546 is macOS 5.0.0-test-icons, build 1605393546.
var MacOS_5_0_0_test_icons_1605393546 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-test-icons [Build: 1605393546]",
	Sign:     "1rnOEpGr6oT3yTCVAawE3dv5PUKSOk6Bq0lzcTwEin+OqX3BTklCgHG1MtLriqmo2WPCEGQj2CPa23zBdrxWBw==",
}

// Android_3_5_0_1605605389 is Android 3.5.0, build 1605605389.
var Android_3_5_0_1605605389 = ClientVersion{
	Platform: "Android",
	Version:  "3.5.0 [Build: 1605605389]",
	Sign:     "trH8DtnmPwjwv0jpx+tgryFK8RiVvyKswC8MH+HxIqgD68WooDxdn8R9xee5HkwV+Q38o2F444uqTMdAOk6SCQ==",
}

// MacOS_5_0_0_beta33_rc2_1605608215 is macOS 5.0.0-beta33-rc2, build 1605608215.
var MacOS_5_0_0_beta33_rc2_1605608215 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta33-rc2 [Build: 1605608215]",
	Sign:     "1JEraSCVPRpNwd+gNLIlr/3C8Pkd1OvEt0IzrtzCVUXLzV8h687TDXNpbkgW6qBBGKrgvso9KTQcvA0wxaYlCA==",
}

// Windows_5_0_0_beta33_rc2_1605675336 is Windows 5.0.0-beta33-rc2, build 1605675336.
var Windows_5_0_0_beta33_rc2_1605675336 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta33-rc2 [Build: 1605675336]",
	Sign:     "zNPcQJ4fFK2GiBIdWfOATig5IRi5lCCiT8yP/zsnZGJkk9uLkOrcc2Rfex0wA1HxyxRdNJ7qQfDJtTNs9LKnCA==",
}

// Windows_5_0_0_beta33_1605693829 is Windows 5.0.0-beta33, build 1605693829.
var Windows_5_0_0_beta33_1605693829 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta33 [Build: 1605693829]",
	Sign:     "2s/ug5ZCiGXIOr25RPtEvtod1l/eb5IwpRZNLBDelBtuSvoiUlF/f7SyWx8m/VSmbihT4zMaSiCC7OyoO6koBA==",
}

// Linux_5_0_0_beta33_1605693829 is Linux 5.0.0-beta33, build 1605693829.
var Linux_5_0_0_beta33_1605693829 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta33 [Build: 1605693829]",
	Sign:     "gYYNWFtZRyNugi6KEuE0t2zqPwOBQq9dAHsvsc1t2sJrm+L91I++gOnus6cmkP3fBdVs9AyMVHlKG/F1OlpgCA==",
}

// Windows_5_0_0_alpha414_1605720501 is Windows 5.0.0-alpha414, build 1605720501.
var Windows_5_0_0_alpha414_1605720501 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-alpha414 [Build: 1605720501]",
	Sign:     "n9V/ZCUORS6ffCe7+ctw8sV3sjw2/IhugPVPyu3d+Xlv0XGcFAVH1pLNiiARpUc5pcqETTE7/a7csaj2Y6PxCQ==",
}

// Windows_5_0_0_new_certificate_test_2_1605794034 is Windows 5.0.0-new_certificate_test-2, build 1605794034.
var Windows_5_0_0_new_certificate_test_2_1605794034 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-new_certificate_test-2 [Build: 1605794034]",
	Sign:     "BPbfHIp2UT8AY6NiSTWixjRY1aSdag7CPBn9cVtzRRWzST1rOFXf3+47IgUYZjBCZarUXY4jotvgXV3N8XQNDw==",
}

// Windows_5_0_0_prev416_1605888535 is Windows 5.0.0-prev416, build 1605888535.
var Windows_5_0_0_prev416_1605888535 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-prev416 [Build: 1605888535]",
	Sign:     "UBynqR4ifIHweVzma4KDs3OjY4iq72u+fmHIyHNRvp3jqjFFqK7jK9hS2UpL0aXl4F4iBub+5r0lPw2Ls7IACw==",
}

// Windows_3_5_6_1606093423 is Windows 3.5.6, build 1606093423.
var Windows_3_5_6_1606093423 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.6 [Build: 1606093423]",
	Sign:     "pjDmXGaZrhbMk8bUoN4/RAJTYnmwLJeyMHm7uH9rXpg3nVlm73kM5BlZwh1ndd2WycxnM3Ubjmhh2cT1AxbgAA==",
}

// Windows_5_0_0_beta34_rc1_1606209261 is Windows 5.0.0-beta34-rc1, build 1606209261.
var Windows_5_0_0_beta34_rc1_1606209261 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta34-rc1 [Build: 1606209261]",
	Sign:     "c+PIL8IDyRHJqEPSCuHXqB2F2b5US8RdbcTufggerigzxGcZ8jC8J+CAzakRco8UtvzfFYzQ0fJ8qPRfSRxlCw==",
}

// Windows_5_0_0_beta34_rc1_1606232731 is Windows 5.0.0-beta34-rc1, build 1606232731.
var Windows_5_0_0_beta34_rc1_1606232731 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta34-rc1 [Build: 1606232731]",
	Sign:     "Ay6sAHt/gjkRPMixIOuIuSXEqU0b+xqIVbqYPkyL0Ty5y//RStK12WilFGynUgisjb9OI7+DcQX3CD7+DWA2CA==",
}

// Windows_5_0_0_beta34_rc2_1606259476 is Windows 5.0.0-beta34-rc2, build 1606259476.
var Windows_5_0_0_beta34_rc2_1606259476 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta34-rc2 [Build: 1606259476]",
	Sign:     "7M3OtL+owcF8B4uWLRUdw5d+F5838V9HXx48u6yH/vX5jgZDuUz4nM3AGY/SGXNumxyY2cvV4Aca/+xR6O5JCQ==",
}

// Windows_5_0_0_beta34_rc2_1606303040 is Windows 5.0.0-beta34-rc2, build 1606303040.
var Windows_5_0_0_beta34_rc2_1606303040 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta34-rc2 [Build: 1606303040]",
	Sign:     "CQI1dcjeQZ7bpqMuqvHanhfXE6O8kjxEQ7kyK3l8Nel0QgY95lMjR9fyH7QI0svRjTdyYTspLODFf1GPJLO2Cg==",
}

// Windows_5_0_0_beta34_1606310756 is Windows 5.0.0-beta34, build 1606310756.
var Windows_5_0_0_beta34_1606310756 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta34 [Build: 1606310756]",
	Sign:     "wVeg7QRNsmcZY/3Mu6iFNB3tlyzLLoECXy6oXU/f+ioCOdRTN0Vz6aJ2uv5LdBnpu8MnJZzvvI9vCEj6I8B/Ag==",
}

// Linux_5_0_0_beta34_1606310756 is Linux 5.0.0-beta34, build 1606310756.
var Linux_5_0_0_beta34_1606310756 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta34 [Build: 1606310756]",
	Sign:     "D6XRdF0v40le6gVyYmhbPzgm3AB6FQaErQst3urdiHnDuV++K8TZuOQGvF93LElexj/0xr1lOvJH9EjERq8PAA==",
}

// MacOS_5_0_0_beta34_1606310756 is macOS 5.0.0-beta34, build 1606310756.
var MacOS_5_0_0_beta34_1606310756 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta34 [Build: 1606310756]",
	Sign:     "orRhmHrTr7yWhhb9cEtHOSzKPrFYPz7de0SZ7oQ87hPoYoQ6EtMXqYVgdiySDmf0Sc91hTFfem4svMHICy59AA==",
}

// Windows_3_5_6_1606312422 is Windows 3.5.6, build 1606312422.
var Windows_3_5_6_1606312422 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.6 [Build: 1606312422]",
	Sign:     "I5EAPoSvsZ7nic6nCFUw+WdFCNf1NYuOTzrR9A7x0S9J1NYp2zrzktmr2jkhVy6huytftxEOeOOVz+CO10tbAg==",
}

// Linux_3_5_6_1606312422 is Linux 3.5.6, build 1606312422.
var Linux_3_5_6_1606312422 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.6 [Build: 1606312422]",
	Sign:     "qMOwz9/kR+NHyL6AcBW+EnA9rvoWCgnIXH8vIGYtDNPHUR8cxPqPoFKH5nq+7I0F2hrK6k+ynkffjYKmmQt3AQ==",
}

// OSX_3_5_6_1606312422 is OS X 3.5.6, build 1606312422.
var OSX_3_5_6_1606312422 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.6 [Build: 1606312422]",
	Sign:     "AamXAvJnm3Wx/O+2LHgxesEZyF1GuVONvqmaCB+1hFdgWR8w1aot41Z4Cd2Q9wGBCNkMYzmD8tXus2sF44LXBg==",
}

// Windows_5_0_0_qa_1_1606395781 is Windows 5.0.0-qa-1, build 1606395781.
var Windows_5_0_0_qa_1_1606395781 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-1 [Build: 1606395781]",
	Sign:     "lOb+Byvfl5q4SWM7MpUELtoF99xsxSkukJv0HeuigRXcU7mAlZqVohvPqLnzfL6PARdAvuC+DNhWGJCZpjCTCg==",
}

// Windows_3_5_7_1606519399 is Windows 3.5.7, build 1606519399.
var Windows_3_5_7_1606519399 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.7 [Build: 1606519399]",
	Sign:     "9pGLtJ0cZsQD9+6dF95Xo8b2aaOet+Iojt0etvdh+52cOA75R4YylSx/d8zxPDxTucQckxdXE/VWaDVl8m37Aw==",
}

// Windows_3_5_7_1606578603 is Windows 3.5.7, build 1606578603.
var Windows_3_5_7_1606578603 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.7 [Build: 1606578603]",
	Sign:     "C79G/8lxs/UjWynS0oUfdy0x9uxSsQ5ZyJ/5PCTHDpW1slXYpYuyK6idx9Q3WVvGCqh4gwEVKWjK95GZh0BmBw==",
}

// Windows_5_0_0_beta35_rc1_1606766504 is Windows 5.0.0-beta35-rc1, build 1606766504.
var Windows_5_0_0_beta35_rc1_1606766504 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta35-rc1 [Build: 1606766504]",
	Sign:     "StQamBy80FwOQExWnWkJlhh7Uj+VrWA1H4BEZI3HOJu085HhB0fEFGo4x2JDqB6/KvySmFGtJC/WvbGAZWSKAQ==",
}

// Linux_5_0_0_beta35_rc1_1606766504 is Linux 5.0.0-beta35-rc1, build 1606766504.
var Linux_5_0_0_beta35_rc1_1606766504 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta35-rc1 [Build: 1606766504]",
	Sign:     "Z4364TYcGtzQ1vdteQiRT7+/8rVFrxYGnOMKzx7Q3Hm7l06vg0c/e+cdmcQzOv58dNCfiJ13NfskL0NT89MTCQ==",
}

// Windows_5_0_0_beta35_rc2_1606832721 is Windows 5.0.0-beta35-rc2, build 1606832721.
var Windows_5_0_0_beta35_rc2_1606832721 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta35-rc2 [Build: 1606832721]",
	Sign:     "YeVsqKnNE01vrPDdqBhPyPrvwlShOxyzx5pZEK8EaXGgGGVNPMgJeNRasLIeuuPpg5fndnzMDatbrzI9UoCHCA==",
}

// Windows_5_0_0_beta35_1606908024 is Windows 5.0.0-beta35, build 1606908024.
var Windows_5_0_0_beta35_1606908024 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta35 [Build: 1606908024]",
	Sign:     "plojmhz1rW1PRgIv9/aYgM+TYTX/vS5Y0iAl3WdbOGQ+5mvZvFxdXAsf2fTGIXYfnRpuSuFkdqCKZPLgr9chBQ==",
}

// Linux_5_0_0_beta35_1606908024 is Linux 5.0.0-beta35, build 1606908024.
var Linux_5_0_0_beta35_1606908024 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta35 [Build: 1606908024]",
	Sign:     "U3+3R1uwwRHWYwCjuZXR/nYo9tKKTLsTeYW6Am8M94rHE0tOa4c+qHKka8KXx/6expxE7TOsegPO2V49mDzkBA==",
}

// MacOS_5_0_0_beta35_1606908024 is macOS 5.0.0-beta35, build 1606908024.
var MacOS_5_0_0_beta35_1606908024 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta35 [Build: 1606908024]",
	Sign:     "ShAz+0gQkLMPJXkUAdt+WTiz6Av8XA++9VxEPsyKzyH1W5NW+riKeN8cutzlbXjR92/6YbxQSaLR6HpkmzT0Bw==",
}

// Windows_5_0_0_cobra_testing_12_1607080844 is Windows 5.0.0-cobra-testing-12, build 1607080844.
var Windows_5_0_0_cobra_testing_12_1607080844 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-12 [Build: 1607080844]",
	Sign:     "OubSgh/L2aojRfR2VnloVTiqop7ZpL1aEXiXEcWrIXcPBoXCH75Gmgz+TSaNkLYdZXq9WM0AMovRs0zmMgCWCA==",
}

// Windows_5_0_0_beta36_rc1_1607093951 is Windows 5.0.0-beta36-rc1, build 1607093951.
var Windows_5_0_0_beta36_rc1_1607093951 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta36-rc1 [Build: 1607093951]",
	Sign:     "Po++JwnBihgUIaS1dsExjMNm9Bj6N6CIIN9f8/l5fKuJm5KtQKefRaJ2M8xTVJvmVatAFgaukVFRStGs0lGfBw==",
}

// MacOS_5_0_0_beta36_rc1_1607093951 is macOS 5.0.0-beta36-rc1, build 1607093951.
var MacOS_5_0_0_beta36_rc1_1607093951 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta36-rc1 [Build: 1607093951]",
	Sign:     "05nGKBwK3J8Bs9clvybUT/9zwdD2TLWXP9UPuWhbV7+u/WKTdM2hn+7op5ySNXwycvhp2pSDHq19EThFVg9oDA==",
}

// Windows_5_0_0_beta36_rc3_1607430517 is Windows 5.0.0-beta36-rc3, build 1607430517.
var Windows_5_0_0_beta36_rc3_1607430517 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta36-rc3 [Build: 1607430517]",
	Sign:     "P5AF2va7qMnlJNd5FzMNT5sbSVffXSa16i0nCHJSy2ZZ/lMdajkh8q+Pbo6ojWTjoDgAnjyWiCWpE1iBPWCbCg==",
}

// Linux_5_0_0_beta36_rc3_1607430517 is Linux 5.0.0-beta36-rc3, build 1607430517.
var Linux_5_0_0_beta36_rc3_1607430517 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta36-rc3 [Build: 1607430517]",
	Sign:     "JFWNtdiuetTrzjkylKVCazY1jEkAZL8Hraoo+19Ab6ARHS2YuCJABjFqtajEVp0FQBNTpv0J5jJqLc7eIP/eDw==",
}

// Windows_3_5_7_1607443312 is Windows 3.5.7, build 1607443312.
var Windows_3_5_7_1607443312 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.7 [Build: 1607443312]",
	Sign:     "OPT1d2hY3OQ2ttnvo49Z194xw/4Gga9z17XpjJewz1VOOnjccxyRZ825dCHOFr98uXPaqz2qrF8e34h5yV7gCw==",
}

// Linux_3_5_7_1607443312 is Linux 3.5.7, build 1607443312.
var Linux_3_5_7_1607443312 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.7 [Build: 1607443312]",
	Sign:     "m57O4tD7r4fjDBMaspzMepMfRvzioE+m6D39a7ng+1b1PUSQ8avMvGnHTsKtWSbatV04NuJrugMPQn9nqUq9Dw==",
}

// Windows_5_0_0_beta36_rc4_1607500856 is Windows 5.0.0-beta36-rc4, build 1607500856.
var Windows_5_0_0_beta36_rc4_1607500856 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta36-rc4 [Build: 1607500856]",
	Sign:     "38FCIdIPrGjOnWK4KM/caY4o3m/39ERRArrXJKf7eV+wYgxPQAt+S8QX1vkO+BaesVDnS+W/iODefXopulm8DQ==",
}

// Windows_5_0_0_beta36_1607523167 is Windows 5.0.0-beta36, build 1607523167.
var Windows_5_0_0_beta36_1607523167 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta36 [Build: 1607523167]",
	Sign:     "t7cctqp5xDsGv483zVlCTNWR9LcM1d5zuNzUlSTtDWyCF9ZelngfcemmRQkvnanf7TTk8Pf/S87nFiNQQAGVCA==",
}

// Linux_5_0_0_beta36_1607523167 is Linux 5.0.0-beta36, build 1607523167.
var Linux_5_0_0_beta36_1607523167 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta36 [Build: 1607523167]",
	Sign:     "Pn8itVGKVYc0zhUm1KizpQSXOc+WlP0InmlqQOG8JSL0GxddSAlyIeXr5kS4aRLpUZQZbS6PUJp8jSOB6LdqAA==",
}

// MacOS_5_0_0_beta36_1607523167 is macOS 5.0.0-beta36, build 1607523167.
var MacOS_5_0_0_beta36_1607523167 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta36 [Build: 1607523167]",
	Sign:     "1UCA/1K9xISm7O0AyS1TVoxY4nsm/McOOkUlT5wB+JSswUFarJIZ1e9haNhkSLyFSb6wThqLdkYXdk4k5vHKCg==",
}

// Windows_5_0_0_qa_4_1607596631 is Windows 5.0.0-qa-4, build 1607596631.
var Windows_5_0_0_qa_4_1607596631 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-4 [Build: 1607596631]",
	Sign:     "P/zCNJDTm7PrpvywBjW8mkudAOqJy6YGIuN8lkSVleIlacUkcg3Pf2D6WNrI0ypzpDUjM49O9RT9Fpcso6joAA==",
}

// Windows_5_0_0_cobra_testing_14_1607689476 is Windows 5.0.0-cobra-testing-14, build 1607689476.
var Windows_5_0_0_cobra_testing_14_1607689476 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-14 [Build: 1607689476]",
	Sign:     "OMylK9JqoSXD7lRUQCurbbbVSKQWGrgZLKUlaCbKoSgaFklkXg+W8nJa1VkZVK20F3XjUCuT8xr+NAZayPDXCA==",
}

// Windows_5_0_0_beta36_1_rc1_1607948316 is Windows 5.0.0-beta36.1-rc1, build 1607948316.
var Windows_5_0_0_beta36_1_rc1_1607948316 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta36.1-rc1 [Build: 1607948316]",
	Sign:     "uAQOpxqBN443sY1/OWWS6FO/KAGZPZ80oKMD9KNnxJivR4OfSlNUJ0jEQ1RoUSCU9c1+bi3QJb81Hz9PnuFbAg==",
}

// Windows_5_0_0_beta36_1_1608110690 is Windows 5.0.0-beta36.1, build 1608110690.
var Windows_5_0_0_beta36_1_1608110690 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta36.1 [Build: 1608110690]",
	Sign:     "STiDCl7Kj1EjmOp5+7NK6l0llqUi/s23HpSomIrHpsOR/2Ldt+oMlb71/P/t1UMzvZwsmVx6KL12K+145jxHBg==",
}

// Linux_5_0_0_beta36_1_1608110690 is Linux 5.0.0-beta36.1, build 1608110690.
var Linux_5_0_0_beta36_1_1608110690 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta36.1 [Build: 1608110690]",
	Sign:     "7A5o7obP9A51a9lOr5WH0+0NHk7sTf16pGsWytcm6VZgmEvPNcLyGW5RELWw0nBjvz3IV1M6gvbsaLQT9S87Dw==",
}

// MacOS_5_0_0_beta36_1_1608110690 is macOS 5.0.0-beta36.1, build 1608110690.
var MacOS_5_0_0_beta36_1_1608110690 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta36.1 [Build: 1608110690]",
	Sign:     "PjpkGLcBzWNTfAYM72zXim6DanVRtUQoJitqYswSjimqNQMzbqIhZ8UeWDQ33wRlhNyNkur0hXic+1+5iuFRCA==",
}

// Windows_5_0_0_qa_8_1608135862 is Windows 5.0.0-qa-8, build 1608135862.
var Windows_5_0_0_qa_8_1608135862 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-8 [Build: 1608135862]",
	Sign:     "qYz1+vWdonG84Y3a+LE3Hs+DnNiNZtiiESsMNCKuYU5DkyD4QYIuiWT+uHTg+RYRSVWFNHFN0AuX5sNIAdleBA==",
}

// Windows_5_0_0_cobra_testing_15_1608206477 is Windows 5.0.0-cobra-testing-15, build 1608206477.
var Windows_5_0_0_cobra_testing_15_1608206477 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-15 [Build: 1608206477]",
	Sign:     "svRhaBEAhUo98qG241fzuYIrWntfHcmJkN2GDVAbX3TOOxK3H/rjYnwVDzvFB7xYV0OWzB9i2bFwuZU4ygI/AA==",
}

// Windows_3_5_7_1608224421 is Windows 3.5.7, build 1608224421.
var Windows_3_5_7_1608224421 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.7 [Build: 1608224421]",
	Sign:     "JNCW+UhoRIQdkVVw3scJ+8elQLRZDrUzdV467950yuIJmxD/egLBV9fFMHo3puP3xpxZtVH6Z1I4UzWViGs5Dg==",
}

// Linux_3_5_7_1608224421 is Linux 3.5.7, build 1608224421.
var Linux_3_5_7_1608224421 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.7 [Build: 1608224421]",
	Sign:     "bC9tQa+Zp3Xd6tC6eQV6qBzlgktKps0EOD5UjQl2MK6yriAppcDZJmB9Dl9ov2RKe8XtzsGmplRGFUqQThnBAw==",
}

// OSX_3_5_7_1608224421 is OS X 3.5.7, build 1608224421.
var OSX_3_5_7_1608224421 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.7 [Build: 1608224421]",
	Sign:     "62bxnpUQY/CcupgUFjVDKAjNxKFBS8WkqtLMBBRhekLhjMsuQFMhrhJjULWKUYQ50hJ60ECxYLZJF3UDUkvXAQ==",
}

// Windows_5_0_0_qa_12_1608565516 is Windows 5.0.0-qa-12, build 1608565516.
var Windows_5_0_0_qa_12_1608565516 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-12 [Build: 1608565516]",
	Sign:     "5SbZhNARPlPnXG70s6MagMv/UVCcCILkHsma4WEgg97s+E1v+aimSf6p31ntJ/VvGjqUrOY5NqZzlwJaYQQuDA==",
}

// Windows_5_0_0_qa_13_1608646134 is Windows 5.0.0-qa-13, build 1608646134.
var Windows_5_0_0_qa_13_1608646134 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-13 [Build: 1608646134]",
	Sign:     "8Nb+pKZMN7Vm2a0qRZ75qnBFA1vphunnXAGiyiPPXEI34K5CifVZS0Pyj3d8ToCJF5PjuiCCCBdV3PhWZeovBQ==",
}

// Windows_5_0_0_cobra_testing_16_1608713116 is Windows 5.0.0-cobra-testing-16, build 1608713116.
var Windows_5_0_0_cobra_testing_16_1608713116 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-16 [Build: 1608713116]",
	Sign:     "51G/VI7TJMQ3RK7+x5X4/aRgR/UFkj9eozJGVrIWfwddm/9MALTMxX/FpyjE0WAenztutNb7swdV79G0J3eABw==",
}

// Windows_5_0_0_qa_16_1610030909 is Windows 5.0.0-qa-16, build 1610030909.
var Windows_5_0_0_qa_16_1610030909 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-16 [Build: 1610030909]",
	Sign:     "5WWukoB3E68xz0323iWLmBUP+uZr6eHqnnoEyAhcvPr7BUTvKfg3zJ9Enq7lBTI7S+XzW6OuixdtL8ZjNgBXBg==",
}

// Windows_3_5_7_1610311072 is Windows 3.5.7, build 1610311072.
var Windows_3_5_7_1610311072 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.7 [Build: 1610311072]",
	Sign:     "n/vzqeISJJ5y9IqIkq54fKJbuUwBtzIwfKg6iAQfetTtrLgSCg/U6wI1oXkL1RmYb0x4M5C9Si6P+K4Mr9JzBw==",
}

// Linux_3_5_7_1610311072 is Linux 3.5.7, build 1610311072.
var Linux_3_5_7_1610311072 = ClientVersion{
	Platform: "Linux",
	Version:  "3.5.7 [Build: 1610311072]",
	Sign:     "3IEt+rUBL8IiwS96zAZuG0ut3nBnb1aNZUUgz/NAi8fk/9ZFJeT6HVO4eEhP0WusLlOBSDHGMaTrpy/jY1kWCw==",
}

// Windows_5_0_0_beta37_rc1_1610378934 is Windows 5.0.0-beta37-rc1, build 1610378934.
var Windows_5_0_0_beta37_rc1_1610378934 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta37-rc1 [Build: 1610378934]",
	Sign:     "ZTrRD70O7gGT9rOMiIm3VJDsHAhv89ynoQu2NGRkCTog7wFlUFoH69217QuQh4VahLZnqxG0EGXAcQ4M7H5TCA==",
}

// Windows_5_0_0_beta37_rc2_1610414299 is Windows 5.0.0-beta37-rc2, build 1610414299.
var Windows_5_0_0_beta37_rc2_1610414299 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta37-rc2 [Build: 1610414299]",
	Sign:     "qN94HkW71COjtJnjcOX5SCxoA0iHjJpIjK38lReA7AU9/9ML+ZRJgAcXnnQ67FvaaxcBX/AfhVK78ws+eGeHAw==",
}

// Windows_5_0_0_beta37_1610450631 is Windows 5.0.0-beta37, build 1610450631.
var Windows_5_0_0_beta37_1610450631 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta37 [Build: 1610450631]",
	Sign:     "BeV97Z10p287D+U+2VvwcNqsvct9+un7qWB0xtVDXliwkFD1QhUAiTYJJK4V7Q/f1CbuHrfJvR/UCdBnCR+eDg==",
}

// Linux_5_0_0_beta37_1610450631 is Linux 5.0.0-beta37, build 1610450631.
var Linux_5_0_0_beta37_1610450631 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta37 [Build: 1610450631]",
	Sign:     "RLHIBAUIoJtUad236IQMd0vXMW4B4s0FFGlMECTDxIHzr46COc05cH7I3FEJnR7rYZP/SI/hKXHZHpkGhu2vDg==",
}

// MacOS_5_0_0_beta37_1610450631 is macOS 5.0.0-beta37, build 1610450631.
var MacOS_5_0_0_beta37_1610450631 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta37 [Build: 1610450631]",
	Sign:     "j2yR9VA99by1kMMzXucsPOPeZK4lhOGtDgHtUyZwPFbpaMGhpEoD0fWRP0itYbN5/pVctEj65pHtmbOdn3uVDA==",
}

// Windows_5_0_0_beta38_rc1_1610453987 is Windows 5.0.0-beta38-rc1, build 1610453987.
var Windows_5_0_0_beta38_rc1_1610453987 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta38-rc1 [Build: 1610453987]",
	Sign:     "Fyp9Us6JCwqmi6gVMicMNwBf5OVeDJZCOML12WotGCUeA5o1LHm4Th9OaETekLrGBrXQ9ZW5qZP1Bj+6kXdqCA==",
}

// Windows_5_0_0_qa_18_1610541782 is Windows 5.0.0-qa-18, build 1610541782.
var Windows_5_0_0_qa_18_1610541782 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-18 [Build: 1610541782]",
	Sign:     "rMko21JaGQNIPBoh4nHU7e+g+pZ4JS6PfZkPbzb+pBP/n3TgStBAYV7G5zASWyNTvQg+FTIq+DvpBqDdTRetBA==",
}

// Windows_5_0_0_cobra_testing_17_1610555339 is Windows 5.0.0-cobra-testing-17, build 1610555339.
var Windows_5_0_0_cobra_testing_17_1610555339 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-17 [Build: 1610555339]",
	Sign:     "CPnazN0TB00PjwXdKs15Sg1k04Bf+k2PK1jlqRhoJA1m5JRY7S/hwVS9qax4/rbPiLSqoVjnVWQKDLgaYsLwAA==",
}

// Windows_5_0_0_cobra_testing_18_1610623794 is Windows 5.0.0-cobra-testing-18, build 1610623794.
var Windows_5_0_0_cobra_testing_18_1610623794 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-18 [Build: 1610623794]",
	Sign:     "EDZ1yruwOZ6ierSDnmF4bqTDxH2Hlg/fOEBnvigxAt6Iw2+QVLJCT3h5inT1Z8dI/jRJ6uboQWGeA0ct44z5Bg==",
}

// Windows_5_0_0_cobra_testing_19_1610706840 is Windows 5.0.0-cobra-testing-19, build 1610706840.
var Windows_5_0_0_cobra_testing_19_1610706840 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-19 [Build: 1610706840]",
	Sign:     "RohNZcSUAocMBlL7hIPXEf6dNkwJ4gPSKyu2rWoIqqahSwkUZMZJd7oOxo48pLi4FCK6Yios0765hTjB5a3bBg==",
}

// Windows_5_0_0_qa_19_1610957172 is Windows 5.0.0-qa-19, build 1610957172.
var Windows_5_0_0_qa_19_1610957172 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-19 [Build: 1610957172]",
	Sign:     "PHke9RTp7JY4Z3M1v0W38XuiSfeIcVBRi/SFBZLomKeEvgImMLtFCIoXLctCg0jEYOaFZOaiLdBoaqB4khJjCA==",
}

// Windows_5_0_0_qa_20_1610968143 is Windows 5.0.0-qa-20, build 1610968143.
var Windows_5_0_0_qa_20_1610968143 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-20 [Build: 1610968143]",
	Sign:     "kk6gWzbJON42PZ3H7C/OgLeUuBdimPk4w0shBmI8m/mMzwmdbZt5LID6runNtOxDDqgRgy1joSLH+Q0nluUxBw==",
}

// Windows_5_0_0_beta38_rc2_1611137742 is Windows 5.0.0-beta38-rc2, build 1611137742.
var Windows_5_0_0_beta38_rc2_1611137742 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta38-rc2 [Build: 1611137742]",
	Sign:     "dCDRgusRRRn1dqKZ+ZsNS0+E/DhRyMrINX0kXz3RZ6dpcLqPxkz261aln5R2RhVr8+ZNGqJxUyx/aMyeeWotDQ==",
}

// Windows_5_0_0_cobra_testing_20_1611147479 is Windows 5.0.0-cobra-testing-20, build 1611147479.
var Windows_5_0_0_cobra_testing_20_1611147479 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-20 [Build: 1611147479]",
	Sign:     "1f+kVrqWb2uEQskZ/68uyy/kfA4IgI+XAq0/qcA66N1Oj9/BmZ0J95PmsK1QI4K7lWF6x2MnMRcFfTIx3yOgBw==",
}

// Windows_5_0_0_beta38_rc3_1611148781 is Windows 5.0.0-beta38-rc3, build 1611148781.
var Windows_5_0_0_beta38_rc3_1611148781 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta38-rc3 [Build: 1611148781]",
	Sign:     "2Kz0r4ytX3/aAowczPp4nLV8M4Pvq7f1NZdMRJXvqOWnF5rGkkylHYLdZO4v1PfR5dANVTSHEQCR5lhI1h6oCg==",
}

// Windows_5_0_0_beta38_1611230438 is Windows 5.0.0-beta38, build 1611230438.
var Windows_5_0_0_beta38_1611230438 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta38 [Build: 1611230438]",
	Sign:     "fqO3H7ytHO7VPdyKmTc59j9/9o4ItdKyTrF+zGtkhlim2aUpILK8Qktho54xICnrpjW27PiPCOLiZppo0yZDDA==",
}

// Linux_5_0_0_beta38_1611230438 is Linux 5.0.0-beta38, build 1611230438.
var Linux_5_0_0_beta38_1611230438 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta38 [Build: 1611230438]",
	Sign:     "J1FpevvYQURafe71i7Jz8yPz81k4l/4xjNFSSndRyH/ldJ7OekJNWDnoKtyZQpuYQJZw4yUI/6kTSMu8yeBrCA==",
}

// MacOS_5_0_0_beta38_1611230438 is macOS 5.0.0-beta38, build 1611230438.
var MacOS_5_0_0_beta38_1611230438 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta38 [Build: 1611230438]",
	Sign:     "eSMRqqp8atJm+SmYTYqxYwYGn0lvX3TTda/yfUcdAQzZSSUY9gPp3cz/WksllScLqDVrmHSvUCsKjySyC2RZBQ==",
}

// Windows_5_0_0_qa_21_1611242317 is Windows 5.0.0-qa-21, build 1611242317.
var Windows_5_0_0_qa_21_1611242317 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-21 [Build: 1611242317]",
	Sign:     "TjEBonIoo3jsUZ71EgJTaNdUu9Uv1IrRN31uEkD1hVOV5j53/Rkl8p5tBqLIqr9kwrZyDTUTnUc8BBZZi/WfAg==",
}

// Windows_5_0_0_qa_23_1611337907 is Windows 5.0.0-qa-23, build 1611337907.
var Windows_5_0_0_qa_23_1611337907 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-23 [Build: 1611337907]",
	Sign:     "P6Pj1Wwenc6M2tEH6kMzu+NVmrONbCK1lR/v49VVxx/N4ZoKg7eGHuNr/drlFfpXT93ADZ84txx1nPiGRbeVAQ==",
}

// Windows_5_0_0_qa_24_1611589480 is Windows 5.0.0-qa-24, build 1611589480.
var Windows_5_0_0_qa_24_1611589480 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-24 [Build: 1611589480]",
	Sign:     "CK1DKUzcEkbg8lnZI5vdR5hH4Otpcex6I5RnIgBaidMQHYETVA854WvFMt1TwDIsmMZUihSnoV8adoYSwLp5Aw==",
}

// Windows_5_0_0_qa_25_1611659620 is Windows 5.0.0-qa-25, build 1611659620.
var Windows_5_0_0_qa_25_1611659620 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-25 [Build: 1611659620]",
	Sign:     "ZNi9tp2NHMe21jrutl7ZIBSA0ATNLxivdxiFwOCp+djwPi9rQZJkMk/Pv/tM1FJ38w3oyadodfsXnrbmK6mbCA==",
}

// Windows_5_0_0_beta39_rc1_1611678252 is Windows 5.0.0-beta39-rc1, build 1611678252.
var Windows_5_0_0_beta39_rc1_1611678252 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta39-rc1 [Build: 1611678252]",
	Sign:     "AzvcyZhPgfBbzkbwxscmdX53szAoGUwy3iXSaksupa+zOBhk7B+mFo7e8VoTaf2dujaJc4nbIwUjDY9ftT83Aw==",
}

// Windows_5_0_0_beta39_1611686251 is Windows 5.0.0-beta39, build 1611686251.
var Windows_5_0_0_beta39_1611686251 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta39 [Build: 1611686251]",
	Sign:     "Mfng59TemCnyhg5QUeqL2FpynbknmDJw+EFo+lG9SzeFTLmOhFDCnBAFls4HihYuNNQpVMWCQfQjE1klB5wXAg==",
}

// Linux_5_0_0_beta39_1611686251 is Linux 5.0.0-beta39, build 1611686251.
var Linux_5_0_0_beta39_1611686251 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta39 [Build: 1611686251]",
	Sign:     "wjuefnSTU0/bsIz9U+YxaIPeW9VB322MfAd0Uo0EMvwAODvtvCI/fJDThceQdSD7rGK7oPZgWv/aAOZV+chSAw==",
}

// MacOS_5_0_0_beta39_1611686251 is macOS 5.0.0-beta39, build 1611686251.
var MacOS_5_0_0_beta39_1611686251 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta39 [Build: 1611686251]",
	Sign:     "CjwaeaX4sBFya5H4Xe6W0sWzVXVgHUqnwi0hXWe2CIIV33OQ/7BwUAL1cMDpkvHO+SatGBUVnHMV7rpjJye7DQ==",
}

// Windows_5_0_0_qa_26_1611743375 is Windows 5.0.0-qa-26, build 1611743375.
var Windows_5_0_0_qa_26_1611743375 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-26 [Build: 1611743375]",
	Sign:     "6eNLhzrKjbbDxu5fAq4E82L2d47JM9k2NyQdndKd+a3CjUoMniuabVYpiaAKQ9hvQI594wykfWBL/0IyfOtBAg==",
}

// Windows_5_0_0_beta40_rc1_1611825049 is Windows 5.0.0-beta40-rc1, build 1611825049.
var Windows_5_0_0_beta40_rc1_1611825049 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta40-rc1 [Build: 1611825049]",
	Sign:     "XCNVtUtw8x2yw9sdtunfwxnhAaH+rgJl0A6gK9o0Z3PVvUNqrxTkj63VAb6E/e/UpM7P3+UI2Dr92bF/ToUzDA==",
}

// MacOS_5_0_0_beta40_rc1_1611825049 is macOS 5.0.0-beta40-rc1, build 1611825049.
var MacOS_5_0_0_beta40_rc1_1611825049 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta40-rc1 [Build: 1611825049]",
	Sign:     "Y4bdkXf1Q6a0g3TcLps4WBzbq9H9bpW5POWxypnk3mhnF7dG0F7fqCgnYjrM/M6ToUxzCoIGzvo8PkRMmWzMDA==",
}

// Windows_5_0_0_cobra_testing_21_1611838875 is Windows 5.0.0-cobra-testing-21, build 1611838875.
var Windows_5_0_0_cobra_testing_21_1611838875 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-21 [Build: 1611838875]",
	Sign:     "HmDuoodGmKHyS0UIGnxw0IiEX6MTAALiEsMglkNomIq+kCDedm4j3Cn0aMuWtreEZT4iKsMzHYXW/VgY1TxyAg==",
}

// Windows_5_0_0_special_build_1611839196 is Windows 5.0.0-special-build, build 1611839196.
var Windows_5_0_0_special_build_1611839196 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-special-build [Build: 1611839196]",
	Sign:     "EP6Me3j4qAPcZFk5twKQu25wsMALNriG/npsD74eDyAsF0KDrwghNgr8dyKARKXz1OElq/dmVneXfX0aIS39DA==",
}

// Windows_5_0_0_pin_msg_redesign_8_1611846460 is Windows 5.0.0-pin-msg-redesign-8, build 1611846460.
var Windows_5_0_0_pin_msg_redesign_8_1611846460 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-pin-msg-redesign-8 [Build: 1611846460]",
	Sign:     "EfGt6AcI1rDMATuhyuAzszC2W1FsmR14sIG9/ny5XeSMTCtj/ji4E/f7YKgjqLcJoQD4OjmfItZHCn4mV5AlCg==",
}

// Windows_5_0_0_beta40_rc2_1611855045 is Windows 5.0.0-beta40-rc2, build 1611855045.
var Windows_5_0_0_beta40_rc2_1611855045 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta40-rc2 [Build: 1611855045]",
	Sign:     "3T71oJon1fHnUNo8ow/GFjv6EsWwN3oX9pfhlqpSDXV5q8jwP8sLt8I1PML64FY8nLvw3TqcnA3MhIodTI1tDA==",
}

// Windows_5_0_0_beta40_rc3_1612189982 is Windows 5.0.0-beta40-rc3, build 1612189982.
var Windows_5_0_0_beta40_rc3_1612189982 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta40-rc3 [Build: 1612189982]",
	Sign:     "dZ/TGdsIrRjB30IXDftr84VKyrfjPmOJmWsUL1k+57tDea4MGYDxJX+JHr8rbBlFNXys04Ryha7XezgBm2ThAA==",
}

// Windows_5_0_0_ava_4_1612264282 is Windows 5.0.0-ava-4, build 1612264282.
var Windows_5_0_0_ava_4_1612264282 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ava-4 [Build: 1612264282]",
	Sign:     "h7KjfWKWtI4n6PnNOGXf8CqjFPpiUE/AqNTtgPzx+JZQBcwk8D7fd+ZVULQ/5vF8IhMZ73jBzUgTVH8sA/fhCA==",
}

// Windows_5_0_0_beta40_rc5_1612288104 is Windows 5.0.0-beta40-rc5, build 1612288104.
var Windows_5_0_0_beta40_rc5_1612288104 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta40-rc5 [Build: 1612288104]",
	Sign:     "lyGduWLlcO6DkaVAabs1oJKJLqNcb7AHbJJo5ZjKELkprjarxBZPERNaucHofSV25ctXZiV2O59dpykaGayVAA==",
}

// Windows_5_0_0_beta40_1612346973 is Windows 5.0.0-beta40, build 1612346973.
var Windows_5_0_0_beta40_1612346973 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta40 [Build: 1612346973]",
	Sign:     "GR+2Y3eTHeZHfwm/CS+BB09dzmbUH6CdU70wpxPXVJjYoJC8e9pXyq15uxSusnw/fSoFSmxBcppCGS1SoJeaCQ==",
}

// MacOS_5_0_0_beta40_1612346973 is macOS 5.0.0-beta40, build 1612346973.
var MacOS_5_0_0_beta40_1612346973 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta40 [Build: 1612346973]",
	Sign:     "2opndwKGTKntwjcl7XsPFAyGgXd4V08lniVSiThWI4lyQ//G3hH6pIlDdtP2heJaeDPgYxaOTZN+n2YzgY90Bw==",
}

// Windows_5_0_0_qa_29_1612453131 is Windows 5.0.0-qa-29, build 1612453131.
var Windows_5_0_0_qa_29_1612453131 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-29 [Build: 1612453131]",
	Sign:     "wwOcA4QHPFSmDdo9q7Et2ulwCBDGpAJdUz7XDftEnacwXlOv8XJjXGhWJLd4iMkjFO9MLz7V8uvHYBRDZxw6CQ==",
}

// Windows_5_0_0_beta41_rc1_1612527693 is Windows 5.0.0-beta41-rc1, build 1612527693.
var Windows_5_0_0_beta41_rc1_1612527693 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta41-rc1 [Build: 1612527693]",
	Sign:     "y+pLyCo6Jiolyth/huD5jLokYhugNgCX8gpxgz/tqdf8YbZln01Xp/ffqAv+O+wwcCb+g+3PtUT9RUIyqWjSBA==",
}

// Windows_5_0_0_beta41_rc2_1612782198 is Windows 5.0.0-beta41-rc2, build 1612782198.
var Windows_5_0_0_beta41_rc2_1612782198 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta41-rc2 [Build: 1612782198]",
	Sign:     "QOCKhkXWxuOr0n7cLYAOWO3256NlMUe1qjHZI2wbpyulspGmc0AXxM5mJvlNCgvLCt2DhRlSXz/fVXcKzZgJBw==",
}

// Windows_3_5_7_1612783432 is Windows 3.5.7, build 1612783432.
var Windows_3_5_7_1612783432 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.7 [Build: 1612783432]",
	Sign:     "IXYGZC3DW9nJgxfUL9bkxA1zPjoI4IEFNRXL+e2aWvjeHC0uHIgJBf7K03Wldj/NXxAcLPW7+LImlaV5MktiCQ==",
}

// Windows_5_0_0_beta41_rc3_1612799472 is Windows 5.0.0-beta41-rc3, build 1612799472.
var Windows_5_0_0_beta41_rc3_1612799472 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta41-rc3 [Build: 1612799472]",
	Sign:     "Hitalp5DXJZmXEGFxurBAZWazJYuwj14/ydZJfYX17yLVMoOAqaJxnOgyPmGuSsLsENKWig2Vyfru/+CB0iyDw==",
}

// Windows_5_0_0_beta41_rc4_1612811479 is Windows 5.0.0-beta41-rc4, build 1612811479.
var Windows_5_0_0_beta41_rc4_1612811479 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta41-rc4 [Build: 1612811479]",
	Sign:     "/bkW44XfGwbDEcVcnQl7ZZvco4Ed4RKHk1ZNnDlInWxrq117B+yYiqLi3AjJEZrhZetn2FFlWyr7bqQsVr1cCQ==",
}

// Windows_5_0_0_qa_33_1612983552 is Windows 5.0.0-qa-33, build 1612983552.
var Windows_5_0_0_qa_33_1612983552 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-33 [Build: 1612983552]",
	Sign:     "8Kcg9pKMuM9DBQE6mn2H2Nc2ihBAN0XuF5GZZlFPFcEiknpe2C9uHQiLj50YIgupAIsSlpzdd5w8DTJj6QJPAQ==",
}

// Windows_5_0_0_beta41_1613053158 is Windows 5.0.0-beta41, build 1613053158.
var Windows_5_0_0_beta41_1613053158 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta41 [Build: 1613053158]",
	Sign:     "arM5NK+6GukhOocniKYs4fzH5tSCZJf3Tag0fNeKRgezH4EkJzc1okAfY6DHcn2322Tlp7gp6MM1olz2QzZODw==",
}

// Windows_5_0_0_pin_msg_redesign_9_1613057624 is Windows 5.0.0-pin-msg-redesign-9, build 1613057624.
var Windows_5_0_0_pin_msg_redesign_9_1613057624 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-pin-msg-redesign-9 [Build: 1613057624]",
	Sign:     "ucYWz+rDavEaGYCTjEn6roFlehswmEumokjKCx95Or8sSMuhkUbST5mA2lDnkhUs4awanSZrdyq8xhq0NaRzCA==",
}

// Windows_5_0_0_beta41_1_rc2_1613065465 is Windows 5.0.0-beta41.1-rc2, build 1613065465.
var Windows_5_0_0_beta41_1_rc2_1613065465 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta41.1-rc2 [Build: 1613065465]",
	Sign:     "2Y2okcAvPB/bGunIziLC16gEBlm+JANHuI6MjoAy5XW8CF0SMIBI1ZyKQ6t8QhvoJ3ftfHjIATsMcDwppgRgDw==",
}

// Windows_3_5_7_1613066709 is Windows 3.5.7, build 1613066709.
var Windows_3_5_7_1613066709 = ClientVersion{
	Platform: "Windows",
	Version:  "3.5.7 [Build: 1613066709]",
	Sign:     "Md4ix51veF2pnYqgZLsLCDc+vyqkh7L/Zh+8FdnZLB1WwWZJSw0Esyq8IzMxLrIl/MjStvycGeYDvwDFRja2AQ==",
}

// OSX_3_5_7_1613066709 is OS X 3.5.7, build 1613066709.
var OSX_3_5_7_1613066709 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.7 [Build: 1613066709]",
	Sign:     "HFQc4teHEP2poBhHpuT4Iin+oV7vuCHrtiQow3w3FAeFXT4EeRT23tKzgOZ0aoLEg2A5kuBC1991UDW/Y62sDw==",
}

// Windows_5_0_0_beta41_1_1613126021 is Windows 5.0.0-beta41.1, build 1613126021.
var Windows_5_0_0_beta41_1_1613126021 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta41.1 [Build: 1613126021]",
	Sign:     "+8yU+kc5XZw2bmEgNDx8HrVLrUhJrNU3zyqeaUgNHGA+uALvkXAE0iJDpyc0GdKC/SXy/8RtQvUtuiuMvtQNBA==",
}

// Linux_5_0_0_beta41_1_1613126021 is Linux 5.0.0-beta41.1, build 1613126021.
var Linux_5_0_0_beta41_1_1613126021 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta41.1 [Build: 1613126021]",
	Sign:     "PG91XlooLYpIMNMAU2k0HOUn074wy7XAEqqV+KpqPuqXjQxaDfAZKJSpW6yPDYnPAwTjqZeC9p/WsjdI1wSWDQ==",
}

// MacOS_5_0_0_beta41_1_1613126021 is macOS 5.0.0-beta41.1, build 1613126021.
var MacOS_5_0_0_beta41_1_1613126021 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta41.1 [Build: 1613126021]",
	Sign:     "e+cvnmV/pxmReDcrxH5b0j4GsXERIeanr8AK6429elCl1oilJZ1J7y2/Hi1ar+AGVkeXq/TueNpKPaM1onTkCQ==",
}

// Windows_5_0_0_qa_37_1613394573 is Windows 5.0.0-qa-37, build 1613394573.
var Windows_5_0_0_qa_37_1613394573 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-37 [Build: 1613394573]",
	Sign:     "wuh38TmceFuGCLh4LOzCa123mtA4u5kURmpisOwx2ct2acevllTnEjO97DBLJ6mP/4pvhbj6UVUYRy6QfAOwCA==",
}

// Windows_5_0_0_qa_38_1613482789 is Windows 5.0.0-qa-38, build 1613482789.
var Windows_5_0_0_qa_38_1613482789 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-38 [Build: 1613482789]",
	Sign:     "9q/muRilnIEL5gECvId5LtQpmrVUpeu4bP+NLLwgxYI2WV+oasj1V4eigh5WQaQjBhz9hVtVbX8G8WpbEHzZDA==",
}

// Windows_5_0_0_beta42_rc1_1613498559 is Windows 5.0.0-beta42-rc1, build 1613498559.
var Windows_5_0_0_beta42_rc1_1613498559 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta42-rc1 [Build: 1613498559]",
	Sign:     "68ojO5AuFDoHKLouHafJveWK381IpwGKXMMGSkhrItnIROuw0RWxvOW9hLRWsUTLq6U88TlGuTPwGbVArJc4DA==",
}

// Windows_5_0_0_qa_50_1613574228 is Windows 5.0.0-qa-50, build 1613574228.
var Windows_5_0_0_qa_50_1613574228 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-50 [Build: 1613574228]",
	Sign:     "8KhK5Ez3Ed5Y5wlKE+ZWF1jIU9Yasqb4QbTxtKfVMNWskBPtkUUPsxfuzrV6kfVYfkLmkGNN2HRiI6jpz7JrBg==",
}

// Windows_5_0_0_beta42_rc2_1613574920 is Windows 5.0.0-beta42-rc2, build 1613574920.
var Windows_5_0_0_beta42_rc2_1613574920 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta42-rc2 [Build: 1613574920]",
	Sign:     "lvA/yy8fuZx3TW4qlIDzTVjxNR5p1ezB12XSLNFZ9fK+PLbUGkkWP7cvWaQCpI/6KXUL+XlEGbDTWAFYSIcPCQ==",
}

// Windows_5_0_0_beta42_1613641112 is Windows 5.0.0-beta42, build 1613641112.
var Windows_5_0_0_beta42_1613641112 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta42 [Build: 1613641112]",
	Sign:     "qdkx8XgseysaZ1QER1Y0hv0LBYbhUSWWKJ5iVS+Lo9nj8d0jA3+WDXG+NeBR+mtUuEMDVstMEfV+sJlvRI8gAg==",
}

// Linux_5_0_0_beta42_1613641112 is Linux 5.0.0-beta42, build 1613641112.
var Linux_5_0_0_beta42_1613641112 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta42 [Build: 1613641112]",
	Sign:     "nrUQ2ldbv3wXRmve1gcEM8WjZPGlwUYKBd1Lb3uE5H7pg0nNBqdI+ofu9CiOO84EHd7cRV4L0yjUw1snxaH1DA==",
}

// MacOS_5_0_0_beta42_1613641112 is macOS 5.0.0-beta42, build 1613641112.
var MacOS_5_0_0_beta42_1613641112 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta42 [Build: 1613641112]",
	Sign:     "fmtt+6+LYCHj/6KPUMGj6CyN2mFiiCg0mIFb4pWe0FtptIOpCRxc3u0SGdrw7UbG7ZOURc85WboHW0VTtupRAw==",
}

// Windows_5_0_0_whip_6_1613731286 is Windows 5.0.0-whip-6, build 1613731286.
var Windows_5_0_0_whip_6_1613731286 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-whip-6 [Build: 1613731286]",
	Sign:     "vOMV9Rxl7jpWU/7yYukL1dhyVljqa+j1vLwyj0ibLo6UFimew4pEGG8GYGR3zcbM53bjWlUkRaEkRl0VQD24DA==",
}

// Windows_5_0_0_beta43_rc1_1613737602 is Windows 5.0.0-beta43-rc1, build 1613737602.
var Windows_5_0_0_beta43_rc1_1613737602 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta43-rc1 [Build: 1613737602]",
	Sign:     "FllNVg/BjC3xRSwsDDhNV+DLxApIY/qxq0ZXJlHQ0caWTmz+VdpBoq6PrQQqC86mx50mp9jT1XAkupuf34rOAA==",
}

// Windows_5_0_0_beta43_rc2_1614094754 is Windows 5.0.0-beta43-rc2, build 1614094754.
var Windows_5_0_0_beta43_rc2_1614094754 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta43-rc2 [Build: 1614094754]",
	Sign:     "aElzPFeKnlfr7bIz81EFEP4uyox78XAiwQdlbL3Dhlq3HpF69PoS2qBwhxAH57Qc7Ja4fltLO6Uqg3jvQzd4AQ==",
}

// Windows_5_0_0_beta43_1614165699 is Windows 5.0.0-beta43, build 1614165699.
var Windows_5_0_0_beta43_1614165699 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta43 [Build: 1614165699]",
	Sign:     "H7/zMsrN3Bo/jBXEO/b24XWZDquhQIFP7HctK/PV16UXY1eGqma13mvjOdZaZVB8uh3bIdQ6TzV6doJyoE0FDA==",
}

// Windows_5_0_0_beta43_1614246086 is Windows 5.0.0-beta43, build 1614246086.
var Windows_5_0_0_beta43_1614246086 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta43 [Build: 1614246086]",
	Sign:     "9XWWaH3/QaDOtWIzjQDX5/9X4YQ91ITBIbYidq1+Ym37f2wfV75OQQu0q1ivCJ6OEJ4z1Z/vCPbqXVSxMYNMCw==",
}

// Linux_5_0_0_beta43_1614246086 is Linux 5.0.0-beta43, build 1614246086.
var Linux_5_0_0_beta43_1614246086 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta43 [Build: 1614246086]",
	Sign:     "NtXpupFRBip1oD3QVwIhhJv+lrGro8Z/bL2FgUbgF121zZNRtf6Om9HW7R1ggqBkHz4UQuyppEUymnrj3BDaCw==",
}

// MacOS_5_0_0_beta43_1614246086 is macOS 5.0.0-beta43, build 1614246086.
var MacOS_5_0_0_beta43_1614246086 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta43 [Build: 1614246086]",
	Sign:     "xXnqateFI77kyYSzIhJdHoqBIR+d+4OCen4tVVs4dRtIyjN1h1/ZjGvx4yljC99/KChI7bPe9VQUJ6wG0DjeCA==",
}

// Windows_5_0_0_beta44_rc1_1614332025 is Windows 5.0.0-beta44-rc1, build 1614332025.
var Windows_5_0_0_beta44_rc1_1614332025 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta44-rc1 [Build: 1614332025]",
	Sign:     "ixE9oYlD4lGWR5F2Hg6PISJqZM+FxP/3lPyiTUCrM1oFEpHkUxVvAwZLXY+z2Csp1jlA7qGxTs6pmzuKa8mUDA==",
}

// Windows_5_0_0_beta44_rc2_1614595863 is Windows 5.0.0-beta44-rc2, build 1614595863.
var Windows_5_0_0_beta44_rc2_1614595863 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta44-rc2 [Build: 1614595863]",
	Sign:     "sAGJ2R9KI9W24RpR8FEswZrvuC5YqSXOyMbn6sJrSeUdjcEYzxnKWd0VbH+W5dnUqZxo0wJN8d3kQCpaQZv6BQ==",
}

// Linux_5_0_0_beta44_rc2_1614595863 is Linux 5.0.0-beta44-rc2, build 1614595863.
var Linux_5_0_0_beta44_rc2_1614595863 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta44-rc2 [Build: 1614595863]",
	Sign:     "gI0yE2iiF3KOVzBXYhdSFHwQFuPzxK0AYojbuF3W/TuysDOFWRrxESpuVBD2LJu0din44O6X5XXsqHAFG2KfDg==",
}

// Windows_5_0_0_beta44_rc3_1614674773 is Windows 5.0.0-beta44-rc3, build 1614674773.
var Windows_5_0_0_beta44_rc3_1614674773 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta44-rc3 [Build: 1614674773]",
	Sign:     "3c0qKcQsJAN5qWbSC/ASSh1A/p3hcYPz2z+OLTsTe3PRM5zdJHmC+2PVeiIX230pYHSgvXFYJpD1wnL5La6KAg==",
}

// Windows_5_0_0_whip_7_1614690487 is Windows 5.0.0-whip-7, build 1614690487.
var Windows_5_0_0_whip_7_1614690487 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-whip-7 [Build: 1614690487]",
	Sign:     "f5lUGaB2clMJ+gOVozjC1UsXOiYLLZEWCBeSxfoN+L9ynh/eFaffzqgG7qG1Org0BOaOBrnrbzRh0J3LREiVCA==",
}

// Windows_5_0_0_beta44_rc7_1614789085 is Windows 5.0.0-beta44-rc7, build 1614789085.
var Windows_5_0_0_beta44_rc7_1614789085 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta44-rc7 [Build: 1614789085]",
	Sign:     "RGjZDlrzl6nElqfjkq30CTQS+m2ouJgvtg01jU8Vp/sgCvL49IeT6+urGfWy9iGZ4pXiRPV/mbj7yJREGIxpAA==",
}

// Windows_5_0_0_beta44_1614848974 is Windows 5.0.0-beta44, build 1614848974.
var Windows_5_0_0_beta44_1614848974 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta44 [Build: 1614848974]",
	Sign:     "Iyu/4a0EaN/5hn8ElIOflqN7MsjMEJy5aI5Yphy2zRioZSpUdK5dvnrWT6tYBxRhQoXoLvwfQv+8es5DJndnBA==",
}

// Linux_5_0_0_beta44_1614848974 is Linux 5.0.0-beta44, build 1614848974.
var Linux_5_0_0_beta44_1614848974 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta44 [Build: 1614848974]",
	Sign:     "woqXRoIuWTRM45KqrrOJ7EXtWWvyK16Vv7TSrByq5ikJGRARRVhsUZY1MKr9VISdyptODiCLfe4j7oUaorZKDA==",
}

// MacOS_5_0_0_beta44_1614848974 is macOS 5.0.0-beta44, build 1614848974.
var MacOS_5_0_0_beta44_1614848974 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta44 [Build: 1614848974]",
	Sign:     "RO/GrBFbLE9ikZ/rXUI2zFjqigoZZ48DqPqjiMjinZqRAzMBuEvGLcP/R0HM8Eu6s1AE07Sym/a0ordbBjtKDg==",
}

// Windows_5_0_0_whip_9_1614852852 is Windows 5.0.0-whip-9, build 1614852852.
var Windows_5_0_0_whip_9_1614852852 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-whip-9 [Build: 1614852852]",
	Sign:     "oUtso4eas4mA0QOFZAX9ec7SDjvwyY2xjaxIeK/j+wn8JTOpPyA+tBQOsig2Cc4Rj0zAGLvc+vNy+OSY0ly7Cg==",
}

// Windows_5_0_0_whip_10_1614865959 is Windows 5.0.0-whip-10, build 1614865959.
var Windows_5_0_0_whip_10_1614865959 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-whip-10 [Build: 1614865959]",
	Sign:     "u9D6EaeOzNu4t8jISUIAHoG8Nl22T3KjFr3EdyUYTvZTtqnxegCQU3KzvPKag/kb3zBQa7qOjqDw8rMUHENfAQ==",
}

// Windows_5_0_0_beta45_rc1_1614934599 is Windows 5.0.0-beta45-rc1, build 1614934599.
var Windows_5_0_0_beta45_rc1_1614934599 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta45-rc1 [Build: 1614934599]",
	Sign:     "K6Zv9Ei7tMnFaIDPYEbtEfjpREEbV9caIlNFS5B8e7yTYxMBbiVFJIayw/Qz3ol1AknD+PjTz+AJcz3sC0CQAw==",
}

// OSX_3_5_7_1614951001 is OS X 3.5.7, build 1614951001.
var OSX_3_5_7_1614951001 = ClientVersion{
	Platform: "OS X",
	Version:  "3.5.7 [Build: 1614951001]",
	Sign:     "dLLLDFIfyHq3IPQf1a3TNPQulXo7fdEzIvSXLO2hyaam8nUUBCLx7T/jCTJTx4D9quZ50sVcSacwNRX7n2CsCQ==",
}

// Windows_5_0_0_beta45_rc2_1614959212 is Windows 5.0.0-beta45-rc2, build 1614959212.
var Windows_5_0_0_beta45_rc2_1614959212 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta45-rc2 [Build: 1614959212]",
	Sign:     "J8GhEHSiJdoijyP/yYuoqbeXjaQTSLWTIPaxuZnoA0OJauLShdmzjI2OvKJlUKCZyv/OW5n805PajYyuR1aCDg==",
}

// Windows_5_0_0_beta45_rc3_1615238124 is Windows 5.0.0-beta45-rc3, build 1615238124.
var Windows_5_0_0_beta45_rc3_1615238124 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta45-rc3 [Build: 1615238124]",
	Sign:     "3KFwVs4/I//ENFqs6rlGjF9vaWbAKXgKDUeS/1gXwx9J2a7WmBJvc0anisRTBhE+dobtZgZFd0o1Z7IJAq73BQ==",
}

// Windows_5_0_0_beta45_1615368890 is Windows 5.0.0-beta45, build 1615368890.
var Windows_5_0_0_beta45_1615368890 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta45 [Build: 1615368890]",
	Sign:     "jym8S5RDNXOdHTLaxwPuGuMt/Ceg+tkCoW7eYEmmuLfe/bP9MiUv0Z1NnxOwcUEr4tLaG4dFk/MwSGq4edToCA==",
}

// Linux_5_0_0_beta45_1615368890 is Linux 5.0.0-beta45, build 1615368890.
var Linux_5_0_0_beta45_1615368890 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta45 [Build: 1615368890]",
	Sign:     "sAzpkX9kjAM5ur710j0mQzI9srFtslieQuyP/QPVdOFhwwxt30RaagY8DT3+vBbiWFCULMvO76Jj4zdwgCutDQ==",
}

// Windows_5_0_0_beta45_1_1615384896 is Windows 5.0.0-beta45.1, build 1615384896.
var Windows_5_0_0_beta45_1_1615384896 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta45.1 [Build: 1615384896]",
	Sign:     "eyjTSk2QIfp5l3bvJPG7Iqxj6SbV/53PrvwYRjyPMha4qu/avV6+4ZpjoFLyoIJ7yCsZBalitXuIYSdlYiFXDQ==",
}

// MacOS_5_0_0_beta45_1_1615384896 is macOS 5.0.0-beta45.1, build 1615384896.
var MacOS_5_0_0_beta45_1_1615384896 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta45.1 [Build: 1615384896]",
	Sign:     "BMAV0hDzcjK9qGKlVNVf24TPt870h1ekUmVs+avbWSuWuJf4vNrJh4dnwFoDbqHi9FOcXVtV74t7ndQF7qpPAw==",
}

// Windows_5_0_0_beta45_2_1615454854 is Windows 5.0.0-beta45.2, build 1615454854.
var Windows_5_0_0_beta45_2_1615454854 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta45.2 [Build: 1615454854]",
	Sign:     "6ttI8HoOkFLukISvSd6FlXfFGdVAHfmNFZkYpzdvwJahKJnJHd3CZ28Wr/mAYOqJUcmSI/LOF4Iek3yuhK8wAg==",
}

// Linux_5_0_0_beta45_2_1615454854 is Linux 5.0.0-beta45.2, build 1615454854.
var Linux_5_0_0_beta45_2_1615454854 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta45.2 [Build: 1615454854]",
	Sign:     "XYeUfntCzUZPNzBsTe8VT3tOzDG/ixJ7erjR6nEXkvXK1wip6vKD1omVfIphIHb3RnqJ15VvndpdwYBOKDToDQ==",
}

// MacOS_5_0_0_beta45_2_1615454854 is macOS 5.0.0-beta45.2, build 1615454854.
var MacOS_5_0_0_beta45_2_1615454854 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta45.2 [Build: 1615454854]",
	Sign:     "w4rCfN66Hw0BGSV+aAzPhouaA8+i0UDA8cPhGqzpRYP+mM2MJbUdGOIXRPRV89/0q3C+ksj8nN6h/Spwj5I2Bw==",
}

// Windows_5_0_0_beta46_rc1_1615454969 is Windows 5.0.0-beta46-rc1, build 1615454969.
var Windows_5_0_0_beta46_rc1_1615454969 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta46-rc1 [Build: 1615454969]",
	Sign:     "E3B4dHkeuNQJ0xMQ4ELVKVNY6fKm9fWe0aqH/kH7Fb8ptozWG8DffUGVZhKdHDN/GaK+xI9hzHtAKp/wFaJ6Dw==",
}

// Windows_5_0_0_beta46_rc2_1615547095 is Windows 5.0.0-beta46-rc2, build 1615547095.
var Windows_5_0_0_beta46_rc2_1615547095 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta46-rc2 [Build: 1615547095]",
	Sign:     "vHL67ZSWhPQDMQQPhUAjB7J5+cpz6RpYYjY7B5t6PG4J7M4pWgqn4MRA7vZycA53LLds8lyGjqdv1QJ676iADw==",
}

// Windows_5_0_0_beta46_rc3_1615974917 is Windows 5.0.0-beta46-rc3, build 1615974917.
var Windows_5_0_0_beta46_rc3_1615974917 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta46-rc3 [Build: 1615974917]",
	Sign:     "HnlUN4wDtU4+yRVWi/EN6P+SBBKg4ni3iDcLZU5tqJnTOsc3N5RUbo/kReNOPl3B4goPaDXztIGBWlgUCodPCg==",
}

// Windows_5_0_0_cobra_testing_30_1615991576 is Windows 5.0.0-cobra-testing-30, build 1615991576.
var Windows_5_0_0_cobra_testing_30_1615991576 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-cobra-testing-30 [Build: 1615991576]",
	Sign:     "bQf9i6oQe72eYT806ilmadztpSX9PkW6/Vzqmf8xtw0pfsjYK+oVPZGrWNKlWtLLQFrKlsD77YHNn0kk1C92BA==",
}

// Windows_5_0_0_beta46_1616059671 is Windows 5.0.0-beta46, build 1616059671.
var Windows_5_0_0_beta46_1616059671 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta46 [Build: 1616059671]",
	Sign:     "v1Or1Lajx76cAcCLKXELMiDxYW+akC09u0ZnCmoBK1uB2/Rp1GRLF3LGCMYtsxphGuHQRZKtLKYKx3kjoqYnBg==",
}

// Linux_5_0_0_beta46_1616059671 is Linux 5.0.0-beta46, build 1616059671.
var Linux_5_0_0_beta46_1616059671 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta46 [Build: 1616059671]",
	Sign:     "fdo0xRlkgr9pXnx7pwm93fbrB6v77tKjs4amTHIc42mD/bX5b9RoKUH9jpjSoWrz7vJbP2eKq/Noiu9wCaQHDQ==",
}

// MacOS_5_0_0_beta46_1616059671 is macOS 5.0.0-beta46, build 1616059671.
var MacOS_5_0_0_beta46_1616059671 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta46 [Build: 1616059671]",
	Sign:     "tvxeVCyEmqifQUW7Q/J1CD0wk9DF5pMNXcc3Go2MwpmboOaBKBE47vLNjFpzNhbK/9L7vbC/MFTiXsXPT48xAA==",
}

// Windows_5_0_0_beta47_rc1_1616085242 is Windows 5.0.0-beta47-rc1, build 1616085242.
var Windows_5_0_0_beta47_rc1_1616085242 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta47-rc1 [Build: 1616085242]",
	Sign:     "q4NCcjigcATvxgLdvXHg2Uyrs2hmbA6gG4YQqnz/FRLseGWfqi2YXAwC8oHQyu4i2uhDtRZk/fwn4HXQFJLRAQ==",
}

// Windows_5_0_0_beta47_rc2_1616094254 is Windows 5.0.0-beta47-rc2, build 1616094254.
var Windows_5_0_0_beta47_rc2_1616094254 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta47-rc2 [Build: 1616094254]",
	Sign:     "h1t7AYO2K/vEuFTFykiZzTVrgV1f1wt+fKYOAzkKFgW3G5r1EhEjgSsi+eDK3dAY7RfdIir2w614axyo3dAECw==",
}

// Windows_5_0_0_co_1_1616188878 is Windows 5.0.0-co-1, build 1616188878.
var Windows_5_0_0_co_1_1616188878 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-co-1 [Build: 1616188878]",
	Sign:     "hEUOcdrheJeNr6Iwbyv5k8ct9vUckqGXgAXCyuq59pLQwzlNvOR0kPzkYuCGomhHF83FtpzqWennSrxRRNJTDg==",
}

// Windows_5_0_0_beta47_rc3_1616533310 is Windows 5.0.0-beta47-rc3, build 1616533310.
var Windows_5_0_0_beta47_rc3_1616533310 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta47-rc3 [Build: 1616533310]",
	Sign:     "7DDJzx/BUON+0MrgBXu3tTbFIRM9ldVZ0DF+KF/q+ra5VRGG2o4FP29yHL2lO50SSXamDl9VhHJzGtDRa2eBBA==",
}

// Windows_5_0_0_beta47_rc4_1616586931 is Windows 5.0.0-beta47-rc4, build 1616586931.
var Windows_5_0_0_beta47_rc4_1616586931 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta47-rc4 [Build: 1616586931]",
	Sign:     "8/FtnNJyBa7aAHjO207Ri1HDryFjg0lxunZb57N5PfOXbxRg+02lVrPusnQ/2fyW4jJiB5umSBNoZzQQpZTHBg==",
}

// Windows_5_0_0_beta47_1616598274 is Windows 5.0.0-beta47, build 1616598274.
var Windows_5_0_0_beta47_1616598274 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta47 [Build: 1616598274]",
	Sign:     "pLqGHf0jAp8bD5faDZR+3tM0+1f11spbb9LPtp6Ai3BljnhUj1xTuP5gldLYE7DXOHbi0mO4vmfPOfLQg4jOAA==",
}

// Linux_5_0_0_beta47_1616598274 is Linux 5.0.0-beta47, build 1616598274.
var Linux_5_0_0_beta47_1616598274 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta47 [Build: 1616598274]",
	Sign:     "y6b4+TK9FF5TrEuHm/YRxk0y0O4PKJeuRd5RX6kun3mOdej/qT0mfEUiAd+kLrR9kaXZbDi3eecHz7tmr1QRAw==",
}

// MacOS_5_0_0_beta47_1616598274 is macOS 5.0.0-beta47, build 1616598274.
var MacOS_5_0_0_beta47_1616598274 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta47 [Build: 1616598274]",
	Sign:     "OSyCUJbA2yHbXcRRmXKHNzTBbEaNKCc4b02vvwJlDcncj2ytkxGfClnj8AROlEK/fcVQPnB70WrTCnIzk4e9BA==",
}

// Windows_5_0_0_qa_48_1_1616670396 is Windows 5.0.0-qa-48-1, build 1616670396.
var Windows_5_0_0_qa_48_1_1616670396 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-48-1 [Build: 1616670396]",
	Sign:     "TvzMODwIax0PwvbZp0iRRMMpiYIT+Xn85i/o3Z6qURz6mxcWS9x43IpQLVYWaYlLvmMz/0CSjX6R4FMKHDZiDw==",
}

// Windows_5_0_0_beta48_rc1_1617015983 is Windows 5.0.0-beta48-rc1, build 1617015983.
var Windows_5_0_0_beta48_rc1_1617015983 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta48-rc1 [Build: 1617015983]",
	Sign:     "QC4hPp3j8hAEseYwLLGw14ED4IhJtWJiJ7lQ9M8GC8eiXo0VFhNzj85yEd+q4f5WKB2vsk5oA1Ze5wFHcvfDCQ==",
}

// Windows_5_0_0_beta48_1617183427 is Windows 5.0.0-beta48, build 1617183427.
var Windows_5_0_0_beta48_1617183427 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta48 [Build: 1617183427]",
	Sign:     "2MYWzoZBjDBhGCmD8y4RsBybuSRtu9fkHyOV8lbgOAKLaYMDPe9ST171hXruA1JltG/ZFlLdJ8eXAiK+aIVCBw==",
}

// Linux_5_0_0_beta48_1617183427 is Linux 5.0.0-beta48, build 1617183427.
var Linux_5_0_0_beta48_1617183427 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta48 [Build: 1617183427]",
	Sign:     "y+dx7mr6oUkKQ36Q1I/7EqiiZGjd+bAQBkN34JYkQMUZ2GjK2WnDhlLUA8MIQlHgiGh9USpL3wC/m16/t/QpBg==",
}

// MacOS_5_0_0_beta48_1617183427 is macOS 5.0.0-beta48, build 1617183427.
var MacOS_5_0_0_beta48_1617183427 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta48 [Build: 1617183427]",
	Sign:     "c9+re8CmXHQ935zGNTsowtaYVaZMXUqPfUomZyuK0vm4Um4TG5IkviDdCdWHXKf9I7EZpUkeruQKGoXyrMFBAw==",
}

// Windows_5_0_0_beta49_rc1_1617889801 is Windows 5.0.0-beta49-rc1, build 1617889801.
var Windows_5_0_0_beta49_rc1_1617889801 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta49-rc1 [Build: 1617889801]",
	Sign:     "lPA6Ofr9yDHjXSBqn6SdlR0UZk/iAE3AXDwtxzixJ6t4ZIuIwD8GS190yMFcxeef0G1DpNL8gRt9+hTtTidLAw==",
}

// Windows_5_0_0_ticket2000_2_1617892719 is Windows 5.0.0-ticket2000-2, build 1617892719.
var Windows_5_0_0_ticket2000_2_1617892719 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ticket2000-2 [Build: 1617892719]",
	Sign:     "3qxvr9U4RlqErjpv7y/3RMRhXzT2ITHDAVA4kJEyuNN4nBviBIFSfcMpj72+l3xRroql5l8hWY1JQw+QLBarDg==",
}

// Windows_5_0_0_beta49_rc2_1618219716 is Windows 5.0.0-beta49-rc2, build 1618219716.
var Windows_5_0_0_beta49_rc2_1618219716 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta49-rc2 [Build: 1618219716]",
	Sign:     "IJQ3Cwo8HcL+rOGHx8sPU1g2pS+2X7OcVgnhkcV8uahLWtDrPf3t6nxbifP6SqRpz6AFV3Uoff9TBLJ9iswIAQ==",
}

// Windows_5_0_0_ticket2000_3_1618230451 is Windows 5.0.0-ticket2000-3, build 1618230451.
var Windows_5_0_0_ticket2000_3_1618230451 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ticket2000-3 [Build: 1618230451]",
	Sign:     "TQYGy9qe7jgJDUPizDnXHhmrpqtr1mHqrok9amqzpVh0BtmztH/6oJfrEIwUy6e10jak6AzlVE6uPeWxvo7fDA==",
}

// Windows_5_0_0_t2000_4_1618303999 is Windows 5.0.0-t2000-4, build 1618303999.
var Windows_5_0_0_t2000_4_1618303999 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-t2000-4 [Build: 1618303999]",
	Sign:     "IrwaQDZ5MGRvSund7xNRBS15/I3kZ9tgpnb5wObTMG6P2HT8Q09Vy6OLKMd7QPnod65yi0xgthMz9XlO+K46DA==",
}

// Windows_5_0_0_beta49_rc3_1618310180 is Windows 5.0.0-beta49-rc3, build 1618310180.
var Windows_5_0_0_beta49_rc3_1618310180 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta49-rc3 [Build: 1618310180]",
	Sign:     "UO+41jnHZ1PdAw6yrs0Oko7Ve/b8AWObnjCAgN+sm2t6/gvhoev5MnNQWIEP5HCRixApCsupHUSZxNRqC7MzAw==",
}

// Windows_5_0_0_qa_49_7_1618321773 is Windows 5.0.0-qa-49-7, build 1618321773.
var Windows_5_0_0_qa_49_7_1618321773 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-49-7 [Build: 1618321773]",
	Sign:     "GMmmiusTijlAUSVDpeEv9YExpEFWdN7aOXztp6uspvgbDF0XfGSbTxDph0OX81AUH0G5C6LOIpde/1Yr6WnJBQ==",
}

// Windows_5_0_0_beta49_1618401668 is Windows 5.0.0-beta49, build 1618401668.
var Windows_5_0_0_beta49_1618401668 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta49 [Build: 1618401668]",
	Sign:     "FnrKgsYT2TlyqBDnBO6RpjrobB5adNC+gsCAOHOWROMDMNeCfGlSDqErldRkkJHbSOA4CZqtDevGI6S53uSkBw==",
}

// Linux_5_0_0_beta49_1618401668 is Linux 5.0.0-beta49, build 1618401668.
var Linux_5_0_0_beta49_1618401668 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta49 [Build: 1618401668]",
	Sign:     "1fnGYinBukr6lBQcjRAkdqqr4M6hBm4e6e3ncZyYdNObK20gNfBGZ58qBUBbnfDKi1BuOkUj+/qsDWb+CdkXAQ==",
}

// MacOS_5_0_0_beta49_1618401668 is macOS 5.0.0-beta49, build 1618401668.
var MacOS_5_0_0_beta49_1618401668 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta49 [Build: 1618401668]",
	Sign:     "V0edFhIRDAK66rJ+8e6hDdXdkA5rf3cOjUS1RD3vwO7yXNuJnx/BT2LXORl6zPLrmtpCxMeR4x6Q8JPXhK23AQ==",
}

// Windows_5_0_0_shorturls_2_1618486773 is Windows 5.0.0-shorturls-2, build 1618486773.
var Windows_5_0_0_shorturls_2_1618486773 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-shorturls-2 [Build: 1618486773]",
	Sign:     "866uLGWsRihCOSp7NcxQB+EYqdA0WF7UONcbU+Y32Yp0VmdKo48X3gKoE+GUS55Rn/PUuVEsn/MmMZuzhRs8Cw==",
}

// Windows_5_0_0_beta50_rc2_1618505526 is Windows 5.0.0-beta50-rc2, build 1618505526.
var Windows_5_0_0_beta50_rc2_1618505526 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta50-rc2 [Build: 1618505526]",
	Sign:     "qlPx8pbXRFZ0fLHRMTk5FzTHsYrssAUg+2Hvnc5gehJu88qtlY/kI27Z+4H/pXps5oxPMAzNUQA0TnLqP+H0DQ==",
}

// MacOS_5_0_0_beta50_rc3_1618776916 is macOS 5.0.0-beta50-rc3, build 1618776916.
var MacOS_5_0_0_beta50_rc3_1618776916 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta50-rc3 [Build: 1618776916]",
	Sign:     "NxxwMZETqUi3jYVyV6kJmv9IBuxohfkrqFSiAXjUESF0b0s7kAztHkv52RC4XzhAqW1Gdk2RruSzStun7MXRDw==",
}

// Windows_5_0_0_beta50_1619006474 is Windows 5.0.0-beta50, build 1619006474.
var Windows_5_0_0_beta50_1619006474 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta50 [Build: 1619006474]",
	Sign:     "6C2xLq1VsibrY2G3DFfx70WWQ3SLbS+frhAMkt6+d5f/actmMj+gHRt6KOazAhnotW5Ei9UPvP48WWZu0QOSAA==",
}

// Linux_5_0_0_beta50_1619006474 is Linux 5.0.0-beta50, build 1619006474.
var Linux_5_0_0_beta50_1619006474 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta50 [Build: 1619006474]",
	Sign:     "TqKfFh0zIEADZgnU5FJhOR8vps03joP9lXV00UgTVHcYSiPHrOqZeYmwHfSVA2ekR/f1x/mPQ1i46NIQmigMAA==",
}

// MacOS_5_0_0_beta50_1619006474 is macOS 5.0.0-beta50, build 1619006474.
var MacOS_5_0_0_beta50_1619006474 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta50 [Build: 1619006474]",
	Sign:     "7svnOYiCRugAZ5EeVZp84uva7fDjMzRMWZf3M9nEkrnJ/jcs36en0WeFAyieKg+OMzt387C91cze56Qq1y0SDQ==",
}

// Windows_5_0_0_qa_51_1_1619041054 is Windows 5.0.0-qa-51-1, build 1619041054.
var Windows_5_0_0_qa_51_1_1619041054 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-51-1 [Build: 1619041054]",
	Sign:     "IhCj67HuwJytBnMDjAw14WZw8WWUv8eoUwLikLyghipDOpx0edYKY/4c/OmbN77PsNP/2ASm+YFdvHDkfLsGAg==",
}

// Windows_5_0_0_beta51_rc1_1619190183 is Windows 5.0.0-beta51-rc1, build 1619190183.
var Windows_5_0_0_beta51_rc1_1619190183 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta51-rc1 [Build: 1619190183]",
	Sign:     "3f81wSWrc6ozo6Me4FaMfefSwov3O+ypfPEgEWvqL/MA5EUB50nn+5poamylF6C3RM6HnQ5T5myuiHEZmzjEDg==",
}

// Windows_5_0_0_beta51_rc2_1619364080 is Windows 5.0.0-beta51-rc2, build 1619364080.
var Windows_5_0_0_beta51_rc2_1619364080 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta51-rc2 [Build: 1619364080]",
	Sign:     "m5VL90gBU8XAETjrBEl3mL2+FpTunI6V7SA98v6wk/Xxedci+VfrVF0yT7nblfiXbcP/aoY2TonC53c4COuqDA==",
}

// Windows_5_0_0_beta51_rc4_1619371671 is Windows 5.0.0-beta51-rc4, build 1619371671.
var Windows_5_0_0_beta51_rc4_1619371671 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta51-rc4 [Build: 1619371671]",
	Sign:     "dCJndDHM9dFMXKbErOL/illlMSLCWWMA+zw+CSmDzIW18l3lJPVsSOCXjfcUJfL1/UGV8SgcKIk2e7yHwW96CQ==",
}

// Windows_5_0_0_beta51_rc4_1619462790 is Windows 5.0.0-beta51-rc4, build 1619462790.
var Windows_5_0_0_beta51_rc4_1619462790 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta51-rc4 [Build: 1619462790]",
	Sign:     "ZyYVsQbax1a0qqCBplYXVEOS7+t5dTr2M1NaHChO5ZrA1AwqJ4IaEwcvJ7AAFRN/eAsp1wu5mYx0VWVFoixTBA==",
}

// Windows_5_0_0_beta51_rc5_1619624829 is Windows 5.0.0-beta51-rc5, build 1619624829.
var Windows_5_0_0_beta51_rc5_1619624829 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta51-rc5 [Build: 1619624829]",
	Sign:     "/QgpIU1qA8KRBBJ8XuiuNhxvd8wslV8rzjS5HJ38lrpowE9kng7L6ZfD+LSpm6lDy2bbsIdmXIcWEIuPwLBLBQ==",
}

// Windows_5_0_0_beta51_1619681979 is Windows 5.0.0-beta51, build 1619681979.
var Windows_5_0_0_beta51_1619681979 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta51 [Build: 1619681979]",
	Sign:     "cBBnWIxmjY2sv1/CR1XZx8qCWTuRE6r85tKom9M3nHtGQwvO/IM0Z3V6CPZvTwt5FrFoxPQKo413pGFgWh8KBw==",
}

// Linux_5_0_0_beta51_1619681979 is Linux 5.0.0-beta51, build 1619681979.
var Linux_5_0_0_beta51_1619681979 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta51 [Build: 1619681979]",
	Sign:     "3jQfwAlAsCcdiPYohGKJMKXzzgKZEH9RJJUdN0P5GMyKFrXQTqo9c8Q/oDr+ZDaNaXTbcgZ89g6HP5y7eN8lBw==",
}

// MacOS_5_0_0_beta51_1619681979 is macOS 5.0.0-beta51, build 1619681979.
var MacOS_5_0_0_beta51_1619681979 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta51 [Build: 1619681979]",
	Sign:     "chXOmkLwweeaCamsCbNGoWSWqMCHITNYTLoGWIRO/CbIydEXBXadY3JwWjMuLcf1VtcMpWVbYKZG7pNOYunPBw==",
}

// Windows_5_0_0_qa_52_2_1619773339 is Windows 5.0.0-qa-52-2, build 1619773339.
var Windows_5_0_0_qa_52_2_1619773339 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-52-2 [Build: 1619773339]",
	Sign:     "gbfc3mE+7/pgfh16Yfivq29Wm+JnCAtWzfkJcwQ5AwKJUq6vi7fy6mXOoE5T6GDjW3PsGTbf9jphdvQcYv/FCA==",
}

// Windows_5_0_0_qa_52_4_1619890509 is Windows 5.0.0-qa-52-4, build 1619890509.
var Windows_5_0_0_qa_52_4_1619890509 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-52-4 [Build: 1619890509]",
	Sign:     "P3TAWnIRWhRs1ngJi6O9bfX/ea616AfhLRRgZ4rt82WxtHsym/+01U7JRNCGIOwvN22XqjnbwlGQ/0cz32MKAg==",
}

// Windows_5_0_0_beta52_rc1_1620060486 is Windows 5.0.0-beta52-rc1, build 1620060486.
var Windows_5_0_0_beta52_rc1_1620060486 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta52-rc1 [Build: 1620060486]",
	Sign:     "1NOx+woysTMhas7SF3CHpG62/9aC3yP8TUEUabTPY56Z8397kAppX7XrSvFdcXffse01DCgJtwal/5Rkq1JgBQ==",
}

// Windows_5_0_0_qa_52_6_1620142606 is Windows 5.0.0-qa-52-6, build 1620142606.
var Windows_5_0_0_qa_52_6_1620142606 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-52-6 [Build: 1620142606]",
	Sign:     "aT/Y8d1/H0y1+aFqZwlJDGUhdY+Y+jVJNPNOxxmv1Y8da+ODp0wCda/WDn6/b2EKNiMDx0levRpfWvRPkE+oAA==",
}

// Windows_5_0_0_beta52_rc2_1620215337 is Windows 5.0.0-beta52-rc2, build 1620215337.
var Windows_5_0_0_beta52_rc2_1620215337 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta52-rc2 [Build: 1620215337]",
	Sign:     "hW6LrgfZbN8e+8a8A61FfoWRvZzNzhXar5edvn8vu9SJ1jMF79/k6jF78LMReS4EybixEj/IADwD0hm0N7FkBA==",
}

// Windows_5_0_0_beta52_1620308356 is Windows 5.0.0-beta52, build 1620308356.
var Windows_5_0_0_beta52_1620308356 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta52 [Build: 1620308356]",
	Sign:     "IdwOkU/80PcmgWroJQoDxlHjFVnsqO+znSf0ZJ5jYIky98t7seFEsl0ln55E5t+z1twPgdjWqU8InnluFDIpDw==",
}

// Linux_5_0_0_beta52_1620308356 is Linux 5.0.0-beta52, build 1620308356.
var Linux_5_0_0_beta52_1620308356 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta52 [Build: 1620308356]",
	Sign:     "M0Pu4YVZ23UMLdXaAMyXdMGnmSsBUGvXRmz0VN1o6xpL0dj+cN6CRWPMnvO+oGfOgA0EE9wIDPICba+PAYKzDg==",
}

// MacOS_5_0_0_beta52_1620308356 is macOS 5.0.0-beta52, build 1620308356.
var MacOS_5_0_0_beta52_1620308356 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta52 [Build: 1620308356]",
	Sign:     "fbY56gISJ/pccZJtcXbEidpbzqlCyKvi4lqoQMAex/L7rEm3jfn2Eil9AYD1VhDP44NkiHqug40DNttOKB5OCw==",
}

// Windows_5_0_0_beta52_1_1620389196 is Windows 5.0.0-beta52.1, build 1620389196.
var Windows_5_0_0_beta52_1_1620389196 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta52.1 [Build: 1620389196]",
	Sign:     "QGIR1wmxFFFk/Rg/+AZlQ11FgtEtIqrD4Z3Rn+VPbwZF0XINSHEt2ouq/KVs38ndVDQONt5HBMZbtw9nRVLCCA==",
}

// Linux_5_0_0_beta52_1_1620389196 is Linux 5.0.0-beta52.1, build 1620389196.
var Linux_5_0_0_beta52_1_1620389196 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta52.1 [Build: 1620389196]",
	Sign:     "J5D3tI8h5q4322hALB0Ok9heqVSNWKDdDvUr+Fq8dkrdI4LtT7lmYq19GOCxSRHAXPSfy8UxjqFJ9IjGW7LWDQ==",
}

// MacOS_5_0_0_beta52_1_1620389196 is macOS 5.0.0-beta52.1, build 1620389196.
var MacOS_5_0_0_beta52_1_1620389196 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta52.1 [Build: 1620389196]",
	Sign:     "aYyUiF51mtkNR0ufTSaufl8fYbWSxn+mxqNi6YMsDK3pDIvJDa6fMKehrHpXaJdY8v1Z7MxP0MHbUQ1m00ESDg==",
}

// Windows_5_0_0_beta53_rc1_1620391678 is Windows 5.0.0-beta53-rc1, build 1620391678.
var Windows_5_0_0_beta53_rc1_1620391678 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta53-rc1 [Build: 1620391678]",
	Sign:     "sMAID1GuMgzVAIWci9+i2MXMqrKD/yt2LtHcaQk3JD/MgGxafAKShIOjHM7c7dTnWDrk2xJbo+pUPsWvOmzyBA==",
}

// Windows_5_0_0_qa_53_2_1620406854 is Windows 5.0.0-qa-53-2, build 1620406854.
var Windows_5_0_0_qa_53_2_1620406854 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-53-2 [Build: 1620406854]",
	Sign:     "2Fsfz4ks8JQL05v1bNN17YfsyW0Oh9J3D24g/u/C0RMm5O0afpmNTkWVbIVYnBxrAbBpWE7gKVM67/X1AoLWBQ==",
}

// Windows_5_0_0_qa_53_3_1620466424 is Windows 5.0.0-qa-53-3, build 1620466424.
var Windows_5_0_0_qa_53_3_1620466424 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-53-3 [Build: 1620466424]",
	Sign:     "1XLrY2RFM466+Y5Tb966Fbx+mNgr8MkyMIXJkxa+43MqFcFHIhJVTh7jlzVLmMXhZWgBqfYhpECkBe1PX+0FDg==",
}

// Windows_5_0_0_beta53_rc3_1620751751 is Windows 5.0.0-beta53-rc3, build 1620751751.
var Windows_5_0_0_beta53_rc3_1620751751 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta53-rc3 [Build: 1620751751]",
	Sign:     "9PzIuMOVKatQJ06ih4P7KLSp9526xYXgJqVZiI3OL0SJJ098q5QQUCM3281maVL8nJUzCzyjAUjQm1VITAsEAQ==",
}

// Windows_5_0_0_beta53_1620812712 is Windows 5.0.0-beta53, build 1620812712.
var Windows_5_0_0_beta53_1620812712 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta53 [Build: 1620812712]",
	Sign:     "I/3f7dKsxA+4Tc+84dCEQmj44t6x0IcCDlum4OHpSB9dg7Pz4OjJEOsLf3WW6iPtG9EF/XrRj0KGee1lrguzBA==",
}

// Linux_5_0_0_beta53_1620812712 is Linux 5.0.0-beta53, build 1620812712.
var Linux_5_0_0_beta53_1620812712 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta53 [Build: 1620812712]",
	Sign:     "FIJQMQnZ5PtFc4qVuw2DTpOOtJW1bisXq+m6mNRwQ18kpsFfi2+Bewyf0RZUbvWk5gJCwAFavsCKUn+Dcf2VAg==",
}

// MacOS_5_0_0_beta53_1620812712 is macOS 5.0.0-beta53, build 1620812712.
var MacOS_5_0_0_beta53_1620812712 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta53 [Build: 1620812712]",
	Sign:     "WGo/nY+Lgdto74deJ1aOxXK0PBT5+ECe7Wu6c4AxdrUMM53w8Tbd4AXkvPjTll+xuYkT1m1b9b/AILP//8IXDw==",
}

// Windows_5_0_0_qa_th_7_1620837606 is Windows 5.0.0-qa-th-7, build 1620837606.
var Windows_5_0_0_qa_th_7_1620837606 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-th-7 [Build: 1620837606]",
	Sign:     "oXkTeSdu+Rp0bQsJX4r+0WkVHJcZZP9nno+9Ch7U7js7wDjRmoN55CxxGYWuV6G3qJef+5NwdUAC/X68BrhsBw==",
}

// Windows_5_0_0_beta54_rc1_1620990757 is Windows 5.0.0-beta54-rc1, build 1620990757.
var Windows_5_0_0_beta54_rc1_1620990757 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta54-rc1 [Build: 1620990757]",
	Sign:     "EILW7wizaSkBoFcvS3n+In64H7jZ6GiNaIoA02iO1+R1z0ty+qarBRlLbGCv2rI6hNnTmfm1fz0UXieaDw2TDw==",
}

// Windows_5_0_0_qa_sea_3_1621467933 is Windows 5.0.0-qa-sea-3, build 1621467933.
var Windows_5_0_0_qa_sea_3_1621467933 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-sea-3 [Build: 1621467933]",
	Sign:     "TkF2YHH7RfJm26M1AW5gmLjxE5Gh2MY2APnr2BPsYsnQcdwmO0/68Tt9/OI/bYoa+fRbIeOCnu3yxuQfcf0fDQ==",
}

// Windows_5_0_0_beta54_rc2_1621608154 is Windows 5.0.0-beta54-rc2, build 1621608154.
var Windows_5_0_0_beta54_rc2_1621608154 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta54-rc2 [Build: 1621608154]",
	Sign:     "urRSFRAlyTZTf/0Xa8sETDs1m4xjU2k5GAZzTr+sktNMAaaSkBqgM6tuCeYmrQvSTuidxxHMvYi4fUn8mfXBDg==",
}

// Windows_5_0_0_qa_ex_1_1621780734 is Windows 5.0.0-qa-ex-1, build 1621780734.
var Windows_5_0_0_qa_ex_1_1621780734 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-ex-1 [Build: 1621780734]",
	Sign:     "J0OeeXYoRwc81sSDvfeK0CFcBqwHH0pnmE2HDLyH4FGxv6QQUGSynDc5sOGmu6JhmBwRQw4dJ7L9+CFi4+K7Dw==",
}

// Windows_5_0_0_beta54_rc3_1621966258 is Windows 5.0.0-beta54-rc3, build 1621966258.
var Windows_5_0_0_beta54_rc3_1621966258 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta54-rc3 [Build: 1621966258]",
	Sign:     "d0KY0/Lr6abJaMm88UyRaWHc2hmQBjDWz3XGPbbGO0Y861aOZFH8Q5h2ker+aGph+XgqL1nNOvsuxkX7tEzqCQ==",
}

// MacOS_5_0_0_beta54_rc3_1621966258 is macOS 5.0.0-beta54-rc3, build 1621966258.
var MacOS_5_0_0_beta54_rc3_1621966258 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta54-rc3 [Build: 1621966258]",
	Sign:     "77zX5UWHKZb7aztyIM8SXTzzHeohDuv9cEZClv7bRIHXJ3ULog3gpm0NlhIuFW0NtuhnvCBb+y0bsk5Z00sfBA==",
}

// Windows_5_0_0_beta54_1622118640 is Windows 5.0.0-beta54, build 1622118640.
var Windows_5_0_0_beta54_1622118640 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta54 [Build: 1622118640]",
	Sign:     "PWa8uSFhmI0+PkOqtGz4RyRy2MAHXJyEIKp/2iJEcT8yesOBuvstu4NS3t3mbSh0wxIbEAqLxz8Sml7qAZYtDA==",
}

// Linux_5_0_0_beta54_1622118640 is Linux 5.0.0-beta54, build 1622118640.
var Linux_5_0_0_beta54_1622118640 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta54 [Build: 1622118640]",
	Sign:     "HCR8uUkq0kVQAW8wckYN+MQWUjKFnSWijRpYHLL6PkY4wQNByKCXYC+ojcFO3DpBt0sh/TvX4y5/s91wu/rMAQ==",
}

// MacOS_5_0_0_beta54_1622118640 is macOS 5.0.0-beta54, build 1622118640.
var MacOS_5_0_0_beta54_1622118640 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta54 [Build: 1622118640]",
	Sign:     "/tnQ4PpOkREsO7cLHAWWA9AUHRNpZmtgRUtp9ggd2S8kXAUHNdbccerHTeMcsAgQ23Xnd7KDhWy2y4NJ8oI9DA==",
}

// Windows_5_0_0_qa_55_1_1622144487 is Windows 5.0.0-qa-55-1, build 1622144487.
var Windows_5_0_0_qa_55_1_1622144487 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-55-1 [Build: 1622144487]",
	Sign:     "P4wWKbQLZt1n/O58icE9zu+QEubXmMqOg+Ge8oCmF9z8qIowtgXLPTJ8n/Qs2jnnE+kIKld+VYIE85k4CtG5DA==",
}

// Windows_5_0_0_beta54_1_1622193586 is Windows 5.0.0-beta54.1, build 1622193586.
var Windows_5_0_0_beta54_1_1622193586 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta54.1 [Build: 1622193586]",
	Sign:     "4NT+15Tj04x37T782oDzIenlmu8B/agc2zuRLKH5L4myzbrJFiUFRSjgV4qIqwOjeGRAea82DSrFEO/RcvXkBw==",
}

// Linux_5_0_0_beta54_1_1622193586 is Linux 5.0.0-beta54.1, build 1622193586.
var Linux_5_0_0_beta54_1_1622193586 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta54.1 [Build: 1622193586]",
	Sign:     "JVanVTTtN1HE4HMpeAGku/vjoXKrBTPokMTei686c4u11hOWB59mtHTtFUkCoyAq70ESFmAt73B5mIRqoN2VBg==",
}

// MacOS_5_0_0_beta54_1_1622193586 is macOS 5.0.0-beta54.1, build 1622193586.
var MacOS_5_0_0_beta54_1_1622193586 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta54.1 [Build: 1622193586]",
	Sign:     "erjNFR3QtPTD533YwkguumPja+LiuqvqqwgPPqLkirRejBQEfkL9LE2kuh4V1TQRILTXHpxSbrFxictQ7S+/CA==",
}

// Windows_5_0_0_beta55_rc1_1622211570 is Windows 5.0.0-beta55-rc1, build 1622211570.
var Windows_5_0_0_beta55_rc1_1622211570 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta55-rc1 [Build: 1622211570]",
	Sign:     "1tSlxxY6iaptmif4rlkotuA0Lg8oXAcjYb07GThuC9CahBVR0qztUvmT3R9HxT5cPMLtIq290O4laleZN1ZaBg==",
}

// Windows_5_0_0_beta55_rc3_1622558414 is Windows 5.0.0-beta55-rc3, build 1622558414.
var Windows_5_0_0_beta55_rc3_1622558414 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta55-rc3 [Build: 1622558414]",
	Sign:     "FVu+gEIcFPAWnGwtB+egdQ7nJ6Wy0cF2ZDu/QdyyB0A/HiAh9vZc0nR+1V5VGGF8pmA4LeJ6gU0+EUTccHrOAw==",
}

// Windows_5_0_0_beta55_1622638893 is Windows 5.0.0-beta55, build 1622638893.
var Windows_5_0_0_beta55_1622638893 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta55 [Build: 1622638893]",
	Sign:     "3J+O2VQDxn3Uv1Rap/iEEY13j0nrzNTNQ51qXdyaMk1QeHrE1q0KQnRyi0hHnhkD4M3EfX6kKNBlJE4xN4AOCQ==",
}

// Linux_5_0_0_beta55_1622638893 is Linux 5.0.0-beta55, build 1622638893.
var Linux_5_0_0_beta55_1622638893 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta55 [Build: 1622638893]",
	Sign:     "srcT6h46YGQHSHpRYHtkB3IypX+bK0Ej1/3OjBZmbcI5PMLGlmsog/Yc+nKh7A98Ri+lniDLXSs9Zr9b24yaDA==",
}

// MacOS_5_0_0_beta55_1622638893 is macOS 5.0.0-beta55, build 1622638893.
var MacOS_5_0_0_beta55_1622638893 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta55 [Build: 1622638893]",
	Sign:     "2gSuGZAel3Q20QvrQblEYo9EzPs8eNcizIqsn1eKi0E5Flmz3nMYOSoB2dtSYoJscfXrZDY9u3qhG4D0dCU1Bg==",
}

// Windows_5_0_0_qa_56_1_1623069200 is Windows 5.0.0-qa-56-1, build 1623069200.
var Windows_5_0_0_qa_56_1_1623069200 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-56-1 [Build: 1623069200]",
	Sign:     "HCnoX2J8AXpbhroYOGJB5tHVWfYUe2JHXonRuB6X411RBMnaVM9c5BU/rUjYjx1D+cISBiB3ks/Hq62efPFmDw==",
}

// Windows_5_0_0_beta56_1623148575 is Windows 5.0.0-beta56, build 1623148575.
var Windows_5_0_0_beta56_1623148575 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta56 [Build: 1623148575]",
	Sign:     "+42FcuaeKG6BKSMW6IHyu+AxuGcFTV8fPfbBr85Zb6U7RRJQmV5eY/q7KJag0JNgYdaH4cjxK8A73p+lFxUFBQ==",
}

// Linux_5_0_0_beta56_1623148575 is Linux 5.0.0-beta56, build 1623148575.
var Linux_5_0_0_beta56_1623148575 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta56 [Build: 1623148575]",
	Sign:     "d9h/sV9KB4sJS3POH0MLBiugngBRNhLvWMD20btZ6eEV4d2UHgKd2dxmd6MQ8arQOk93RXMmRM7x2pUjShV7Aw==",
}

// MacOS_5_0_0_beta56_1623148575 is macOS 5.0.0-beta56, build 1623148575.
var MacOS_5_0_0_beta56_1623148575 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta56 [Build: 1623148575]",
	Sign:     "TAXyB1fdhYHwkKyN0cSGqYebYCHJop34rLRcBZRkWWMhif3qzL2ifdQKLlujnUbS86cOLOKmkzYut1Rj7s5xCg==",
}

// Windows_5_0_0_beta57_rc1_1623161118 is Windows 5.0.0-beta57-rc1, build 1623161118.
var Windows_5_0_0_beta57_rc1_1623161118 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta57-rc1 [Build: 1623161118]",
	Sign:     "XXrsCn5LVz88fH6MHwb8UINFHHOFz+FjeACUfcryMydYk1t5wsweBuQKlhw1cyFyIrpcujzacKaX2NsurX6gDQ==",
}

// Linux_5_0_0_beta57_rc1_1623161118 is Linux 5.0.0-beta57-rc1, build 1623161118.
var Linux_5_0_0_beta57_rc1_1623161118 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta57-rc1 [Build: 1623161118]",
	Sign:     "hz+mPLe9T7wtKNdiY0fuGBEpyqXNpBwZ8Rg3Z5+C9M26J365jnyT06YBEEm1rn/IPAoYlhjLyFstDByTPxSYBg==",
}

// Windows_5_0_0_beta57_rc2_1623419125 is Windows 5.0.0-beta57-rc2, build 1623419125.
var Windows_5_0_0_beta57_rc2_1623419125 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta57-rc2 [Build: 1623419125]",
	Sign:     "kn4sz9UrXAM07VKrgUDtdmhzf2ovkS3GCvGjYDnMGqLG9Y7vfCC+vbVY835ywmhuRAU66OD5PjeaOqQpfdDEDQ==",
}

// Linux_5_0_0_beta57_rc2_1623419125 is Linux 5.0.0-beta57-rc2, build 1623419125.
var Linux_5_0_0_beta57_rc2_1623419125 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta57-rc2 [Build: 1623419125]",
	Sign:     "HUpyxKD7u8KNS2DJSA0aKqyQqQRGLNpIHLjXtqzOj4xlkvGyAFE5bsWPrZ9Hf6noRXPwLtwiaw5rlG/K3+aPDA==",
}

// MacOS_5_0_0_beta57_rc2_1623419125 is macOS 5.0.0-beta57-rc2, build 1623419125.
var MacOS_5_0_0_beta57_rc2_1623419125 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta57-rc2 [Build: 1623419125]",
	Sign:     "i/v9mxtaL7CDRCV9iZl0X2koxaPh9n/I+yJJFPCYK0HdMMLl//ycPwTrDhuoap2kBpAxKmv7vUxGo/TkKZ4pBw==",
}

// Windows_5_0_0_qa_57_2_1623680173 is Windows 5.0.0-qa-57-2, build 1623680173.
var Windows_5_0_0_qa_57_2_1623680173 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-57-2 [Build: 1623680173]",
	Sign:     "1CS4vp7navBSNTNntt89PBiPS23UvF2xZtxcYuV5NO/t3D66rr8VE8H5QAwLJohb4cpA4fg1fthRUNRW7Zr4Ag==",
}

// Windows_5_0_0_qa_57_3_1_1623703105 is Windows 5.0.0-qa-57-3-1, build 1623703105.
var Windows_5_0_0_qa_57_3_1_1623703105 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-57-3-1 [Build: 1623703105]",
	Sign:     "RpsilUqhdtlAuG7+DxhoyWm6M3qNE/T1+0rqHY/KTFXPRpHHCbst0ptk0c8io5oiCczUgHGCEGqNyuIsTZKRAA==",
}

// Windows_5_0_0_beta57_1623800045 is Windows 5.0.0-beta57, build 1623800045.
var Windows_5_0_0_beta57_1623800045 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta57 [Build: 1623800045]",
	Sign:     "f6P6tAWc0csS3J6z4ZoNI2wF+czRe3Ncnx3R/+hnExxBK+7DBAFyHE9MwVYeSSN4xsOA4vtaCUtwCLFrvjg/DA==",
}

// Linux_5_0_0_beta57_1623800045 is Linux 5.0.0-beta57, build 1623800045.
var Linux_5_0_0_beta57_1623800045 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta57 [Build: 1623800045]",
	Sign:     "4mlATVye7twoeQt/01a3jekU84Cgqrvq3S2BESJqn7z6GlKWioikxhqAf9Uixp68jngoYRbxczFWZygnOEr5DQ==",
}

// MacOS_5_0_0_beta57_1623800045 is macOS 5.0.0-beta57, build 1623800045.
var MacOS_5_0_0_beta57_1623800045 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta57 [Build: 1623800045]",
	Sign:     "jB9zs897RiF+FPLKIOyzMc6PsVck1ao0T1bc3QIqxlQiu4mlOtqqQKblbLwKxsHaPRfi26rddW4kZv+uy3hHBA==",
}

// MacOS_5_0_0_beta58_rc1_1623801564 is macOS 5.0.0-beta58-rc1, build 1623801564.
var MacOS_5_0_0_beta58_rc1_1623801564 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta58-rc1 [Build: 1623801564]",
	Sign:     "6xcgBUtFJYVhcexJEj5M+ittBqiUqyE6dN7NOUVNUKFlPSW6WOItyfhMThfaKvWSx269JXGhstDNLDlMfyHGDQ==",
}

// Windows_5_0_0_qa_ex_3_1623837149 is Windows 5.0.0-qa-ex-3, build 1623837149.
var Windows_5_0_0_qa_ex_3_1623837149 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-ex-3 [Build: 1623837149]",
	Sign:     "HmWWH9D3rROfkK/IzLSueEh/tlDmhMGnuoimwUp0CvWiR9p5KVMVtfqUtcgbs1+yMH47pICya0OsFBtAXSxLAg==",
}

// Windows_5_0_0_beta58_rc2_1623852877 is Windows 5.0.0-beta58-rc2, build 1623852877.
var Windows_5_0_0_beta58_rc2_1623852877 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58-rc2 [Build: 1623852877]",
	Sign:     "D+/TAor1uNx+HQMRnNlUt8CMMe07ZNOrWCR/0boroIZI5CoT0A6sxNSG7y3KrqkiA6AIPaW4qm1BKMvk2yDUAQ==",
}

// Linux_5_0_0_beta58_rc2_1623852877 is Linux 5.0.0-beta58-rc2, build 1623852877.
var Linux_5_0_0_beta58_rc2_1623852877 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58-rc2 [Build: 1623852877]",
	Sign:     "OZzSs8Ewad603y5RVcKgDrBxvsLlae2IyAHqrXDKydOHaLgWqUrpgXMdFNfdc4AzKlCoPB4FMxjaEZ01tGP+Bw==",
}

// MacOS_5_0_0_beta58_rc2_1623852877 is macOS 5.0.0-beta58-rc2, build 1623852877.
var MacOS_5_0_0_beta58_rc2_1623852877 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta58-rc2 [Build: 1623852877]",
	Sign:     "gajkW7AbAOCohBsnBLMcT8S1Y94ZFvcok6kL+qYcHBED9nFu5K3P+8EpEhlkE1VZcn9Z94+Tgk189DBoKVNOAg==",
}

// Windows_5_0_0_beta58_rc3_1624026633 is Windows 5.0.0-beta58-rc3, build 1624026633.
var Windows_5_0_0_beta58_rc3_1624026633 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58-rc3 [Build: 1624026633]",
	Sign:     "WMq45OVM7rnpUwuTfh9y9WG3fwXJ43Dk0qbSuBFC7f3AzRbg1EUds5I5S34rGgGIQ9SdkcmQRNRkIMwfchm0Bg==",
}

// Linux_5_0_0_beta58_rc3_1624026633 is Linux 5.0.0-beta58-rc3, build 1624026633.
var Linux_5_0_0_beta58_rc3_1624026633 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58-rc3 [Build: 1624026633]",
	Sign:     "P+rPi0kjdb4ulRX2laTuc76kV4212iqpNiD8qX6DTFfArKWpieuWJN50vMTKC+nuLZzH1A5qLzkvPxMyewaHBA==",
}

// Windows_5_0_0_beta58_rc4_1624036539 is Windows 5.0.0-beta58-rc4, build 1624036539.
var Windows_5_0_0_beta58_rc4_1624036539 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58-rc4 [Build: 1624036539]",
	Sign:     "heTHLhy1J59lfdBAHM+ecgx2v5xe3t+Xx8yq6+98n7Lij0HC0q2zdiU8IUHTsOwe85hp/OPAmmCdnPEzZAKKAg==",
}

// Linux_5_0_0_beta58_rc4_1624036539 is Linux 5.0.0-beta58-rc4, build 1624036539.
var Linux_5_0_0_beta58_rc4_1624036539 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58-rc4 [Build: 1624036539]",
	Sign:     "AkxU9a8nfSze9gL4gi+QyWM5DlLXr8dGgRDE/IuRY9ZlhmD3o+z0X1qbPDILrRQPczehB/XpXr//2+LciNVBAA==",
}

// Windows_5_0_0_beta58_rc5_1624277263 is Windows 5.0.0-beta58-rc5, build 1624277263.
var Windows_5_0_0_beta58_rc5_1624277263 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58-rc5 [Build: 1624277263]",
	Sign:     "OQheemlgDUJl30ASzoE7udK5TLjrMXtwsr0s/xNN6RvAdJThDgXHrc7eJlX1onOh55QYJ7D5i14L2y8wzAEnBw==",
}

// Linux_5_0_0_beta58_rc5_1624277263 is Linux 5.0.0-beta58-rc5, build 1624277263.
var Linux_5_0_0_beta58_rc5_1624277263 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58-rc5 [Build: 1624277263]",
	Sign:     "bWckVdW+pjHN+C/aUtNxwGC0l5j7UsxFQwdYXK6Q84KfT5Obnouw5wV5OHIGsZLQZOTzIQuldnS/H8eLAjhsCA==",
}

// Windows_5_0_0_beta58_rc6_1624358903 is Windows 5.0.0-beta58-rc6, build 1624358903.
var Windows_5_0_0_beta58_rc6_1624358903 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58-rc6 [Build: 1624358903]",
	Sign:     "TqxAa0e7Udtw41Zxiq+FsDeAZd6a6yGzgoEChUTmAWAMxVOZyjguex+CDRqD2uT6Y4zFXpZAZK6RTLr9XEeJCw==",
}

// Linux_5_0_0_beta58_rc6_1624358903 is Linux 5.0.0-beta58-rc6, build 1624358903.
var Linux_5_0_0_beta58_rc6_1624358903 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58-rc6 [Build: 1624358903]",
	Sign:     "BC3qch2uaVLbdJTcah5Q9QPwF4EuZvoW2/pX1sr77zYTWbCKI42+numvUHLzw1lHUdDetcWuX8CrAE85/aIsDA==",
}

// Windows_5_0_0_beta58_rc7_1624443135 is Windows 5.0.0-beta58-rc7, build 1624443135.
var Windows_5_0_0_beta58_rc7_1624443135 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58-rc7 [Build: 1624443135]",
	Sign:     "AGBGNWmorqdMMS+1fB96g4nkGKNTc6247kL0qI+mwKZTfwr1+TzujBuMYmIj+J1PfKbIC59PgJqX6CKr3ExrBg==",
}

// Linux_5_0_0_beta58_rc7_1624443135 is Linux 5.0.0-beta58-rc7, build 1624443135.
var Linux_5_0_0_beta58_rc7_1624443135 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58-rc7 [Build: 1624443135]",
	Sign:     "y/vxPOYzgYE1ENvSMRLNOG6L0VZnDGVSCicVBp1XYh+eLRN3c3E7A2YrY2ieR0CWlsSnaxlZV8sjwFvA14OGBg==",
}

// Windows_5_0_0_beta58_1624455116 is Windows 5.0.0-beta58, build 1624455116.
var Windows_5_0_0_beta58_1624455116 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58 [Build: 1624455116]",
	Sign:     "QFUj7EwAWIFHDDwtUZVgxwc0O1yAvT7EISiq1djSXuackwNNwz8oF6HbGp41oYGYHIrDdmsEt1ElSD3kNRVeCA==",
}

// Linux_5_0_0_beta58_1624455116 is Linux 5.0.0-beta58, build 1624455116.
var Linux_5_0_0_beta58_1624455116 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58 [Build: 1624455116]",
	Sign:     "jfouQH+p0WODpGqWgGhC2a058Fw2R23aAeqzXGF3bcurwPteQC+ry9qxzxDNgEgLlNfR2oKI9KtgA9rQSzQrAg==",
}

// MacOS_5_0_0_beta58_1624455116 is macOS 5.0.0-beta58, build 1624455116.
var MacOS_5_0_0_beta58_1624455116 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta58 [Build: 1624455116]",
	Sign:     "nhsrLH/r0PgQ7DFotJyUHlNeV9ODPRJ9S08XmIt1Kv8f6IZ4RrC6FGZK8FUSsjo9ZKS/G1cjzkmoq79Mhm8ABA==",
}

// Windows_5_0_0_beta58_1_1625041456 is Windows 5.0.0-beta58.1, build 1625041456.
var Windows_5_0_0_beta58_1_1625041456 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta58.1 [Build: 1625041456]",
	Sign:     "JiV6OaRnC+Mhp4JHWXL4cMlOuSYDMmco9gJxccSRLxc2bWg7LvrlEtp/BT0UTge0r5bTPgGLYmdbZHtvjSZcDw==",
}

// Linux_5_0_0_beta58_1_1625041456 is Linux 5.0.0-beta58.1, build 1625041456.
var Linux_5_0_0_beta58_1_1625041456 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta58.1 [Build: 1625041456]",
	Sign:     "dev3UTiE5hsVr0VRElPtXNiipt4WpbeEElWiYq9RZSrJAXZd1qsg6B6uCDkkyuvK0AoerVyU/c6DzRp0kNJPDw==",
}

// MacOS_5_0_0_beta58_1_1625041456 is macOS 5.0.0-beta58.1, build 1625041456.
var MacOS_5_0_0_beta58_1_1625041456 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta58.1 [Build: 1625041456]",
	Sign:     "7nnuj2cd193D377ldCy3Wc07DYBLjfgNoYrEAyOUeh8hZ9Vrw0RxKuTrMO3T0E8t6/uadGd1vjb3dLlnQctvDA==",
}

// Windows_5_0_0_beta59_rc3_1625125975 is Windows 5.0.0-beta59-rc3, build 1625125975.
var Windows_5_0_0_beta59_rc3_1625125975 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta59-rc3 [Build: 1625125975]",
	Sign:     "8sGyQ/Q8N6v/4faHlpUEDqxBRqRIFhjvtRKWy4k2LakQJxEyKt7xnCYCAeB+3B8U6TVUpMxtOhqD/c8Ut3jqBA==",
}

// Linux_5_0_0_beta59_rc3_1625125975 is Linux 5.0.0-beta59-rc3, build 1625125975.
var Linux_5_0_0_beta59_rc3_1625125975 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta59-rc3 [Build: 1625125975]",
	Sign:     "m0ySGjCY+/24C4E4iBhJtUB8Ih9xCK9puPDfFOXz4SJ6ujL6Zrd0YKi3NcOzuZfEX4Py+mPUNv31bCGNtDhtAg==",
}

// Windows_5_0_0_beta59_rc5_1625222996 is Windows 5.0.0-beta59-rc5, build 1625222996.
var Windows_5_0_0_beta59_rc5_1625222996 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta59-rc5 [Build: 1625222996]",
	Sign:     "fqd6gm3Jm+Ve4JblcOltdDF3HJlJbzib8+M5spAb8xLVX/VqcAizl4l7Mwtx8zfn/UIFS2NKJPwh6Ms29vXoBA==",
}

// Linux_5_0_0_beta59_rc5_1625222996 is Linux 5.0.0-beta59-rc5, build 1625222996.
var Linux_5_0_0_beta59_rc5_1625222996 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta59-rc5 [Build: 1625222996]",
	Sign:     "jmH2WNbLL1N4Ksd2fnv8f67EbIkUpBbSP90vJ2z1fqd897qgFk9GyeaB6oNiEOrRMCCljAoSiA4d3RqSlTxYBw==",
}

// Windows_5_0_0_beta59_rc6_1625281448 is Windows 5.0.0-beta59-rc6, build 1625281448.
var Windows_5_0_0_beta59_rc6_1625281448 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta59-rc6 [Build: 1625281448]",
	Sign:     "pyIvf+Wz+aG94jRRIjf68suzIDZgpmPF3lYNiI2LnPqbBYPlQVI55Y7eEIOKauS+B7YTPFyNZ5tD4xpc5huZAQ==",
}

// Linux_5_0_0_beta59_rc6_1625281448 is Linux 5.0.0-beta59-rc6, build 1625281448.
var Linux_5_0_0_beta59_rc6_1625281448 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta59-rc6 [Build: 1625281448]",
	Sign:     "BHdeMnjdTGSufoVpfsItgWhVYPpmpa7/GPxgG2uZ7AWbc2aGJXalQDuseQNS4sTuFl6Q7tvu2VGpDNH3loZaAA==",
}

// Windows_5_0_0_beta59_1625645480 is Windows 5.0.0-beta59, build 1625645480.
var Windows_5_0_0_beta59_1625645480 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta59 [Build: 1625645480]",
	Sign:     "xPJZ36s3ym/JpRqX1SKdjmrTEsdvWhBg0PZhSKxeShCa4xN6QfZCaTI74DYHKRlkVk1mCg/48RAqXSqFK+SRDQ==",
}

// Linux_5_0_0_beta59_1625645480 is Linux 5.0.0-beta59, build 1625645480.
var Linux_5_0_0_beta59_1625645480 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta59 [Build: 1625645480]",
	Sign:     "LApcwrOY7fJC+Wz9PjIbi5nC+IUueI2dfjWVgTgzBUcP2VJeKgGguxe9JOiEZlPLJ/si6373CnQRFkqqVZTICA==",
}

// MacOS_5_0_0_beta59_1625645480 is macOS 5.0.0-beta59, build 1625645480.
var MacOS_5_0_0_beta59_1625645480 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta59 [Build: 1625645480]",
	Sign:     "Xp1bEbN3q24cAGtudGE4QSCDjCBJRe7r7LQsRc3HMaL2TuskcgvkYZpxvDcScyiP+pIpTGVEajet8mcB8i5cDw==",
}

// Windows_5_0_0_qa_60_0_1626366283 is Windows 5.0.0-qa-60-0, build 1626366283.
var Windows_5_0_0_qa_60_0_1626366283 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-60-0 [Build: 1626366283]",
	Sign:     "uUVj3p8rTKE28iUmqvdUKHe2YL06jiYiq9EFuUhlWFf9L8dYeF2UyZPKWCZxuFND+5AZjStqrRhTAhD8VUMXCA==",
}

// Windows_5_0_0_qa_60_5_1626875020 is Windows 5.0.0-qa-60-5, build 1626875020.
var Windows_5_0_0_qa_60_5_1626875020 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-60-5 [Build: 1626875020]",
	Sign:     "7RDryAgGn574+k74H/9SQ62KB2Xk8ETUR8r1A00I28PjKwSz2sW6QPvDtpy0iFxwFkamMLv7InNjJMCG/KExBA==",
}

// Windows_5_0_0_beta60_rc1_1627029564 is Windows 5.0.0-beta60-rc1, build 1627029564.
var Windows_5_0_0_beta60_rc1_1627029564 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta60-rc1 [Build: 1627029564]",
	Sign:     "UKVg25AJjOyGTyqg5VZkjhLQtUGtuhUJMxtRFH/cYnJbBWxiHNPB/lU/Z373d8PbbPe7lQg3qItRu8eW4NG/Bg==",
}

// Linux_5_0_0_beta60_rc1_1627029564 is Linux 5.0.0-beta60-rc1, build 1627029564.
var Linux_5_0_0_beta60_rc1_1627029564 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta60-rc1 [Build: 1627029564]",
	Sign:     "rQc/sgqxYPz3LEEk9sooKNV6D8sy9pyi9i6gK+M+8tT7atD14NfBkwaZRGVriuAZFbJsYok1u7AosWMm9CYtBw==",
}

// Windows_5_0_0_beta60_rc2_1627281941 is Windows 5.0.0-beta60-rc2, build 1627281941.
var Windows_5_0_0_beta60_rc2_1627281941 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta60-rc2 [Build: 1627281941]",
	Sign:     "MF6QJ9AALuRoZXX6nuNH9P/nHzlUekyTm5s5AxwxCKauWlXZGlFSDC/0BZvaqJ+3OKLJP0O3IVqsl4FKBAH8BQ==",
}

// Windows_5_0_0_beta60_rc3_1627315911 is Windows 5.0.0-beta60-rc3, build 1627315911.
var Windows_5_0_0_beta60_rc3_1627315911 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta60-rc3 [Build: 1627315911]",
	Sign:     "5PlNPQFVeRwyN6l1h72/aNs5MiLkhLdZZC3tyLeUdxBwsNaiBwi0YYn2sZAMvOMjDY1qfoYla32XYmvwsNXYBA==",
}

// Windows_5_0_0_beta60_rc4_1627382772 is Windows 5.0.0-beta60-rc4, build 1627382772.
var Windows_5_0_0_beta60_rc4_1627382772 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta60-rc4 [Build: 1627382772]",
	Sign:     "s1S2p4xxCZrGMlTyBfvEVxkBHaOM5cgxg7BFvRMvj95KbH0oD7QHnmvSMM9GegJMJkXwOr3pDUa0Edo1rCScCA==",
}

// Windows_5_0_0_beta60_1627453078 is Windows 5.0.0-beta60, build 1627453078.
var Windows_5_0_0_beta60_1627453078 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta60 [Build: 1627453078]",
	Sign:     "jSI9eORmJ0xiFCBTvwJk3O5Iz3T4USd0ccgX1cTaQna9ZjL1e0nEandMq9hlTsd8NmBsh3wuVboK2KpvBRuQBQ==",
}

// Linux_5_0_0_beta60_1627453078 is Linux 5.0.0-beta60, build 1627453078.
var Linux_5_0_0_beta60_1627453078 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta60 [Build: 1627453078]",
	Sign:     "pFd5WxdwkUwPqNk4gz/OPDDKDqH7rtS0mRTYUzzQ3k+bYTrphkDGEs3Py85G0Yww56axzZU4d5TeZXJMt4+IDw==",
}

// MacOS_5_0_0_beta60_1627453078 is macOS 5.0.0-beta60, build 1627453078.
var MacOS_5_0_0_beta60_1627453078 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta60 [Build: 1627453078]",
	Sign:     "qZCDpzLg+j2asXImiwE0JR3mkHQZOmuvm5TFQCP6kPxE057A+dP6Vh+BhG5SDo34ost/2FaDb101zqw59g3/AQ==",
}

// Windows_5_0_0_beta60_1_1627557732 is Windows 5.0.0-beta60.1, build 1627557732.
var Windows_5_0_0_beta60_1_1627557732 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta60.1 [Build: 1627557732]",
	Sign:     "q897lxfc2eM+/G2Eho7YZYIwNyiGS4OemqqDQUW5kjji/117n485HjeO33G0rmevcMZtvd+SK5RwpAskgrMVAQ==",
}

// Linux_5_0_0_beta60_2_1627557732 is Linux 5.0.0-beta60.2, build 1627557732.
var Linux_5_0_0_beta60_2_1627557732 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta60.2 [Build: 1627557732]",
	Sign:     "RNOFeDyPTNnxH1XloujSn0RqYlxDDShp64JJqM4TEQqQjmUcmNlWc+zqMMRx3cwiiLZJi+Q8jBwHYu2xvjCuBA==",
}

// MacOS_5_0_0_beta60_2_1627557732 is macOS 5.0.0-beta60.2, build 1627557732.
var MacOS_5_0_0_beta60_2_1627557732 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta60.2 [Build: 1627557732]",
	Sign:     "AjgLY0OCGCcXB80BDoVyf7Es75R3zW5Dk0wrf2UZDiFrQoVq9KNT+LOuW+vLmsxiLn9h9q5tysEgcNNS50E3AQ==",
}

// Windows_5_0_0_beta60_2_1627637709 is Windows 5.0.0-beta60.2, build 1627637709.
var Windows_5_0_0_beta60_2_1627637709 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta60.2 [Build: 1627637709]",
	Sign:     "H6zjHdy2vQfbtwqMFDKzvGF+NuCi9hfbd2FnPwHKs6G+I+rEAkzcwlq/Zy0SiQbGiXstqzJIitv0GQnlXcFPBw==",
}

// Linux_5_0_0_beta60_2_1627637709 is Linux 5.0.0-beta60.2, build 1627637709.
var Linux_5_0_0_beta60_2_1627637709 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta60.2 [Build: 1627637709]",
	Sign:     "Y0yeGGgL8MqP/TbvPioyN49sZRTF9mfA3f81FLXcfVFUBI+2wmtv7HFO8sjdV8E/eCCHGF/aSnfgycLEqG1xAA==",
}

// MacOS_5_0_0_beta60_2_1627637709 is macOS 5.0.0-beta60.2, build 1627637709.
var MacOS_5_0_0_beta60_2_1627637709 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta60.2 [Build: 1627637709]",
	Sign:     "2vQ+zKtyWmOJta0Pp5nLB4zJhJqsbe2FaJhWGDkm6o2Z7CLxnOWJtGr+EFx0Hwc2LxGSTB/80E7iMpVezw5bCw==",
}

// Windows_5_0_0_beta61_rc1_1627995830 is Windows 5.0.0-beta61-rc1, build 1627995830.
var Windows_5_0_0_beta61_rc1_1627995830 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta61-rc1 [Build: 1627995830]",
	Sign:     "AvO7IWx1bq6c5xrbu4xIJheY87QCjeNwp2D/SZaFvwb+/h0RaBPC3aqGYdzZQCW3OLx3xPyJpY21hvV6aWsaDg==",
}

// Linux_5_0_0_beta61_rc1_1627995830 is Linux 5.0.0-beta61-rc1, build 1627995830.
var Linux_5_0_0_beta61_rc1_1627995830 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta61-rc1 [Build: 1627995830]",
	Sign:     "GYGothXGxbeONpib8ugLs4EvX3KiVO15n+2tlIccbahX2onTAnp8KkierFhw3er3yOlixNsbS7fkUjxrb5V5Aw==",
}

// Windows_5_0_0_beta61_rc2_1628243130 is Windows 5.0.0-beta61-rc2, build 1628243130.
var Windows_5_0_0_beta61_rc2_1628243130 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta61-rc2 [Build: 1628243130]",
	Sign:     "KbUmvVj/ZkoJxZoWQkKGzShkQgG5pzvWtqyfOLIH6Fh4hAgifCiEEoDDjR49rur9suBEJXqTq3MEvAX/D0ZWBw==",
}

// Linux_5_0_0_beta61_rc2_1628243130 is Linux 5.0.0-beta61-rc2, build 1628243130.
var Linux_5_0_0_beta61_rc2_1628243130 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta61-rc2 [Build: 1628243130]",
	Sign:     "vISDWJ16G4kopHt4RA+EF2yo39pio1+zUfN5RuLwV9YLk8d04MOnZbX4Xxtake1xO10BbYmdKd6ChRvwrgXxBA==",
}

// Linux_5_0_0_beta61_rc3_1628513934 is Linux 5.0.0-beta61-rc3, build 1628513934.
var Linux_5_0_0_beta61_rc3_1628513934 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta61-rc3 [Build: 1628513934]",
	Sign:     "cVnjrAppfEj6S+GWGCROE10p28si3SPmdDpoOREP7i4PFatQsiBHe4mtqSUZRwJCB3pmcfCMnFOm/rznmVOyAg==",
}

// MacOS_5_0_0_beta61_rc3_1628513934 is macOS 5.0.0-beta61-rc3, build 1628513934.
var MacOS_5_0_0_beta61_rc3_1628513934 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta61-rc3 [Build: 1628513934]",
	Sign:     "W7mtneojI+IR88Jfrj+uAeidF1ABdB4nAPju/zmfyzh47+1rtD5ZbH3NpVsPb7+XkgQlAX/COCqMCMNvH9LpCg==",
}

// Windows_5_0_0_beta61_1628671407 is Windows 5.0.0-beta61, build 1628671407.
var Windows_5_0_0_beta61_1628671407 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta61 [Build: 1628671407]",
	Sign:     "nNxZolc7hbuY/VqOT4yPyss6yyV/P4WtwARdxk6pMSKu2bjqcoruLS4q326dMn2LURoUosTDzSNkG9si+h1wAQ==",
}

// Linux_5_0_0_beta61_1628671407 is Linux 5.0.0-beta61, build 1628671407.
var Linux_5_0_0_beta61_1628671407 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta61 [Build: 1628671407]",
	Sign:     "UXVnT6nMts902bTVvyz6lElUpJMs1Mfu9KmQ1JqNvipmGo7UBOIYk895ar5LvCv2NubiqhHcfzthK5r7Rs1CDg==",
}

// MacOS_5_0_0_beta61_1628671407 is macOS 5.0.0-beta61, build 1628671407.
var MacOS_5_0_0_beta61_1628671407 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta61 [Build: 1628671407]",
	Sign:     "SWaizGVBbnu76+sk+Ci9it9zM/zNd1yvHexIdsGFD9mTqJFESy4Mp3o2rhu3WUmuQ2IS9O2+5am4og7j5HOXCw==",
}

// Linux_5_0_0_beta62_rc1_1628769114 is Linux 5.0.0-beta62-rc1, build 1628769114.
var Linux_5_0_0_beta62_rc1_1628769114 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta62-rc1 [Build: 1628769114]",
	Sign:     "D7VUKGHrIS5j9woksZrVrm0TZ572X57RJU+GXw83iZH0emr7wmTk7X5uRkkwbCtYJyPnE+8Nq9L37v49d3rTBQ==",
}

// Windows_5_0_0_qa_1925_8_1628773544 is Windows 5.0.0-qa-1925-8, build 1628773544.
var Windows_5_0_0_qa_1925_8_1628773544 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-1925-8 [Build: 1628773544]",
	Sign:     "srPGPy3iqROXxBlFWRlQzT2d2suarS3tSYyp0sxhxYKOAauiLC5JpduVuihpYCal/UNbnzyxs4y1RkyzYLEFCQ==",
}

// Windows_5_0_0_beta62_rc2_1628783944 is Windows 5.0.0-beta62-rc2, build 1628783944.
var Windows_5_0_0_beta62_rc2_1628783944 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta62-rc2 [Build: 1628783944]",
	Sign:     "M7bVp7Q3P56amidg44+Dxx2a+Sned/Sv7e99aVW9Og2cCoF/pjjJ1AAij8tkdFcIgi7aehNVw5etU9S0rqkaBg==",
}

// Linux_5_0_0_beta62_rc2_1628783944 is Linux 5.0.0-beta62-rc2, build 1628783944.
var Linux_5_0_0_beta62_rc2_1628783944 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta62-rc2 [Build: 1628783944]",
	Sign:     "hJ+87Z+9l4RbtW6IUSd0glOld6vJCQESdH3SFQ2aKnPlz79ucpxecsvnnoPHElLyP+UrlfbFTQDCs0N1ts1sCA==",
}

// Windows_5_0_0_beta61_1_1628848434 is Windows 5.0.0-beta61.1, build 1628848434.
var Windows_5_0_0_beta61_1_1628848434 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta61.1 [Build: 1628848434]",
	Sign:     "dHRBtVTXv1vR4stDUyubTFTl0GpttNMOewqOFe2hUbzqCWtLflzNCf4rqTMA7OqH6pjYOkM41Z31QhRPoPZ7CA==",
}

// MacOS_5_0_0_beta61_1_1628848434 is macOS 5.0.0-beta61.1, build 1628848434.
var MacOS_5_0_0_beta61_1_1628848434 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta61.1 [Build: 1628848434]",
	Sign:     "xsGyh80SYE8zarooLP+9ascC2V8ilxEa99gDe4umCJJyVSVIw5wDPCTjur88aqNJnfO57qUZKgEJ+UCIaP91CA==",
}

// Windows_5_0_0_beta62_rc4_1629103760 is Windows 5.0.0-beta62-rc4, build 1629103760.
var Windows_5_0_0_beta62_rc4_1629103760 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta62-rc4 [Build: 1629103760]",
	Sign:     "2zOqY8mu2gVTRMo4+fG81TQ+/GazCBqYue4It7tr6ghP5X0CgBdZnG7oEuSj3L1pNSqlMbT+lMrDwC01cigyAg==",
}

// Linux_5_0_0_beta62_rc4_1629103760 is Linux 5.0.0-beta62-rc4, build 1629103760.
var Linux_5_0_0_beta62_rc4_1629103760 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta62-rc4 [Build: 1629103760]",
	Sign:     "SzRKkIeq/Vte/p8GrqQIUn9AhNEBU2SXZSt5NP30giQYJvMjhWI/eHqOjQA3twPJP4kaWIlCn6pIXDJjWOgoBA==",
}

// Windows_5_0_0_beta62_rc5_1629121366 is Windows 5.0.0-beta62-rc5, build 1629121366.
var Windows_5_0_0_beta62_rc5_1629121366 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta62-rc5 [Build: 1629121366]",
	Sign:     "oOUGiICrDiHuDcferglab4Un/d6n5/Grh5Kbp66csJJarwjsG6h5B2YA9GBfBaSWXzwP3jfkow/FTQ4DnPNADg==",
}

// Windows_5_0_0_qa_1925_10_1629205202 is Windows 5.0.0-qa-1925-10, build 1629205202.
var Windows_5_0_0_qa_1925_10_1629205202 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-1925-10 [Build: 1629205202]",
	Sign:     "Vf2gq3er4aXUpejhr4qIF6zbXRdObg/IqU2srtwih6IMH3dkzs4b2mH6qgmjw90T8c3MAxF5WrU5i/PjRkEtAg==",
}

// Windows_5_0_0_beta62_1629207214 is Windows 5.0.0-beta62, build 1629207214.
var Windows_5_0_0_beta62_1629207214 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta62 [Build: 1629207214]",
	Sign:     "B8zwVN7MrzTaAE3FOmwuAqbI3UO5bU0aFEWBcBVBXU6qRArFhjfzCazSW0qClZcTgjCtzGVRZ1KgYv+yEzCECA==",
}

// Linux_5_0_0_beta62_1629207214 is Linux 5.0.0-beta62, build 1629207214.
var Linux_5_0_0_beta62_1629207214 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta62 [Build: 1629207214]",
	Sign:     "EMgW07cDBM3c/WPPTJwGc3aDWHvoG+aqo3dtE5YAd1Bmia8wpD9YOERxetdp+zhmj7Mhi3JHyBl3VMQlCP2mDA==",
}

// MacOS_5_0_0_beta62_1629207214 is macOS 5.0.0-beta62, build 1629207214.
var MacOS_5_0_0_beta62_1629207214 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta62 [Build: 1629207214]",
	Sign:     "Rn/wdm6PcpPv75tAhlFJe1qf8fmettbn8aWSgSBNe8rxcn3Gnoo2RIJ0E05Nt9TQ85A44OC5WenuceMGb/IABQ==",
}

// Windows_5_0_0_beta63_rc1_1629878569 is Windows 5.0.0-beta63-rc1, build 1629878569.
var Windows_5_0_0_beta63_rc1_1629878569 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc1 [Build: 1629878569]",
	Sign:     "hWjdfWfqXVT4y29UUpEs1VTQs92SHMyYmZpZkLFXA67zerpQVj6IcNqxKraUz1LPr+gGN9+JuvnpB+gcQRTdAg==",
}

// Linux_5_0_0_beta63_rc1_1629878569 is Linux 5.0.0-beta63-rc1, build 1629878569.
var Linux_5_0_0_beta63_rc1_1629878569 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta63-rc1 [Build: 1629878569]",
	Sign:     "ptpUHmBo1Oft9FH6IsFCSWG4UzfoZy/HvP1hilSE5G9WKK79auBC4OHroaryAXhTiv48fyRo2J9Tjz/1pMszCg==",
}

// Windows_5_0_0_beta63_rc2_1629993565 is Windows 5.0.0-beta63-rc2, build 1629993565.
var Windows_5_0_0_beta63_rc2_1629993565 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc2 [Build: 1629993565]",
	Sign:     "4cFmNGL9tn/MfJa3OxUbC9qZfZbxU/UXRrKnIufEOuQf8LbFOLS2fV22afjtgvkHTU6wioGFzAsFBMD408raDg==",
}

// Linux_5_0_0_beta63_rc2_1629993565 is Linux 5.0.0-beta63-rc2, build 1629993565.
var Linux_5_0_0_beta63_rc2_1629993565 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta63-rc2 [Build: 1629993565]",
	Sign:     "VOq4OeSuOfB8LQ9+m08sWq3m1uclLoV+nRIUVxTtnwnw/TsfNzRdTkUYBfwPB4SS0pat/WCzmJPVsPcl2pXsBA==",
}

// Windows_5_0_0_beta63_rc3_1630066856 is Windows 5.0.0-beta63-rc3, build 1630066856.
var Windows_5_0_0_beta63_rc3_1630066856 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc3 [Build: 1630066856]",
	Sign:     "DkoURrQZ/arH2s4IzoEFQW/y8z1T2THdNCS1c1BGrpcv0H52soLTAD01APwmdATxcVeBNaxbzq9vSd5pkGSXCA==",
}

// Windows_5_0_0_beta63_rc4_1630324970 is Windows 5.0.0-beta63-rc4, build 1630324970.
var Windows_5_0_0_beta63_rc4_1630324970 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc4 [Build: 1630324970]",
	Sign:     "FObv14Ezz0Ul6g6fxHRNE6SBsgf/2fTtmfNheSYFJ7SBPJheJ95XR4vZkMz3z5rMDPacz5U9483bXkrVea90BQ==",
}

// Windows_5_0_0_beta63_rc5_1630417664 is Windows 5.0.0-beta63-rc5, build 1630417664.
var Windows_5_0_0_beta63_rc5_1630417664 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc5 [Build: 1630417664]",
	Sign:     "Nh9rSb82sfovpCjNlviF9ekL4y6kinMhVlRr8hNqXSJUKRpdg3SCoxhSFrQ0MJ5MFtMSf80Ey//sYPPR8F+xAQ==",
}

// Linux_5_0_0_beta63_rc5_1630417664 is Linux 5.0.0-beta63-rc5, build 1630417664.
var Linux_5_0_0_beta63_rc5_1630417664 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta63-rc5 [Build: 1630417664]",
	Sign:     "Yit88zeNlcO7/jJUbGOXLRlYvx41XlaembvpwFd7ijb6jF41+zU1EGsISgctd+u0GySlrUtpdAmeQm58tfOhBA==",
}

// Windows_5_0_0_beta63_rc6_1630672687 is Windows 5.0.0-beta63-rc6, build 1630672687.
var Windows_5_0_0_beta63_rc6_1630672687 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc6 [Build: 1630672687]",
	Sign:     "5wPn6pom99AbhEeBdmhwvamGiX3oJfdsfAN/cAqojiYFQ3NL8AxEm2qyPmCyuPrGm5O95iwSYXgsfuMw0VVmCg==",
}

// Linux_5_0_0_beta63_rc6_1630672687 is Linux 5.0.0-beta63-rc6, build 1630672687.
var Linux_5_0_0_beta63_rc6_1630672687 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta63-rc6 [Build: 1630672687]",
	Sign:     "NLw9AYJtn2ui46lAZIVtCeabaJiYIswd7y70iGhxytNNyVjt50/A08PYMYpolwyFo3qVwmjYillg5qBQ6cZ6Bg==",
}

// Windows_5_0_0_beta63_rc8_1630944479 is Windows 5.0.0-beta63-rc8, build 1630944479.
var Windows_5_0_0_beta63_rc8_1630944479 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc8 [Build: 1630944479]",
	Sign:     "TEVmPlLUW0JeIJFSsDjnkFiYI2rsqs6BtLWsxBn7iIeF219KL6SIX1eZHhvdwZk16OLOCOH56UX/0X/RtWY0Aw==",
}

// Windows_5_0_0_beta63_rc9_1631005853 is Windows 5.0.0-beta63-rc9, build 1631005853.
var Windows_5_0_0_beta63_rc9_1631005853 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63-rc9 [Build: 1631005853]",
	Sign:     "btkblgqZvb66caWCIE85HOQu9ULbfSjAfixSVSy6YMBMWfxP9AQWt1lzezjuclA4lNVilWFSm5Uhcl+R3/kvCQ==",
}

// Linux_5_0_0_beta63_rc9_1631005853 is Linux 5.0.0-beta63-rc9, build 1631005853.
var Linux_5_0_0_beta63_rc9_1631005853 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta63-rc9 [Build: 1631005853]",
	Sign:     "V6Re2QIXf87/eWjxz9rJEo2mqK+4jrrY94FkdLeK9Ouprp1daynqQqm2Al9I2ac1QBnnxCZe1LWgcPefh/e9AQ==",
}

// Windows_5_0_0_beta63_1631042126 is Windows 5.0.0-beta63, build 1631042126.
var Windows_5_0_0_beta63_1631042126 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63 [Build: 1631042126]",
	Sign:     "MMX4vnmOgjnSdSBidViX7KO7dd73INKb9rw8dHVCPxqKNeMcLgLst1nFedIqxsr53n97rkmfFcRtBANghSBrDw==",
}

// Linux_5_0_0_beta63_1631042126 is Linux 5.0.0-beta63, build 1631042126.
var Linux_5_0_0_beta63_1631042126 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta63 [Build: 1631042126]",
	Sign:     "aEfO8lGf8WVEg7+z4EuuNWkzlukz89ke7eIGs1rVY7cmUcSti+Wfds1pf16MesYno/E6xfsyIGrWB9lFl0E+BQ==",
}

// MacOS_5_0_0_beta63_1631042126 is macOS 5.0.0-beta63, build 1631042126.
var MacOS_5_0_0_beta63_1631042126 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta63 [Build: 1631042126]",
	Sign:     "F5ZFNd6RE6zzBR7rjfw4IJFcAEPfa2ECcaHgSD5QORBvsvQxHZcEnEXXcLmdddZW2ppiqrdzEKtB/NaVdjRIBw==",
}

// Windows_5_0_0_away_test8_1631200786 is Windows 5.0.0-away-test8, build 1631200786.
var Windows_5_0_0_away_test8_1631200786 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-away-test8 [Build: 1631200786]",
	Sign:     "Irhvv+WQjL5450UmlAOVY/0UdYBSwUl+UE9kCYpaL0S6IjnJ3LRhgO50mAsJQchcdwJGjdATDsY9TMcO/BUPDA==",
}

// Windows_5_0_0_beta63_1_1631268231 is Windows 5.0.0-beta63.1, build 1631268231.
var Windows_5_0_0_beta63_1_1631268231 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta63.1 [Build: 1631268231]",
	Sign:     "HSr40GiVRivm/l6YjTKCNP+njvR7EhpTlkxByOiieI3jedQRyzdS/uxbcIupS6TDWdDsSS0URBTgH1n0FqUKDQ==",
}

// Linux_5_0_0_beta63_1_1631268231 is Linux 5.0.0-beta63.1, build 1631268231.
var Linux_5_0_0_beta63_1_1631268231 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta63.1 [Build: 1631268231]",
	Sign:     "KgpMkgrD4QZcSd1mYi9qVMgUfAjf3VVbKYReVU/nwR2xKAXOiFVAgqZ5DZF16Aq91e5xQvZxQhl8i7umPROZAQ==",
}

// MacOS_5_0_0_beta63_1_1631268231 is macOS 5.0.0-beta63.1, build 1631268231.
var MacOS_5_0_0_beta63_1_1631268231 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta63.1 [Build: 1631268231]",
	Sign:     "kEEqTmZ24fKwAohaUYEvWz97fI2yp2MC9RJgN34F3Y9gUNzc1t/DOyD6xHL4wQF4hWfY3WjIA7lM69Rwt153Aw==",
}

// Windows_5_0_0_beta64_rc1_1631271008 is Windows 5.0.0-beta64-rc1, build 1631271008.
var Windows_5_0_0_beta64_rc1_1631271008 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta64-rc1 [Build: 1631271008]",
	Sign:     "UMxEnfB38gV2FUYiokuJ9hYK1u7ObwA5zoRXa+oAtC5OxEf+PEpsMxBspdKqPllFVS3k+xX0XWx2Q5Gi+ANmBw==",
}

// Windows_5_0_0_beta64_rc2_1631535074 is Windows 5.0.0-beta64-rc2, build 1631535074.
var Windows_5_0_0_beta64_rc2_1631535074 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta64-rc2 [Build: 1631535074]",
	Sign:     "6zYgWnTOR1wRFV+hrAf4muv3pplVUBcrRBnKN97kRv/aEuy1Mgn5ez11EnXFR57dbU9AQjDGPBQRUpJFNj7JBQ==",
}

// Windows_5_0_0_beta64_rc3_1631614018 is Windows 5.0.0-beta64-rc3, build 1631614018.
var Windows_5_0_0_beta64_rc3_1631614018 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta64-rc3 [Build: 1631614018]",
	Sign:     "kGx0a1FrSsYrWJ8BcIWoQo1nw9F4yrO1EuO65uKYO9ZRrrINJrgwaHUZwx5MRc9ajsJFaQdUsXhumCKZKU9hDA==",
}

// Linux_5_0_0_beta64_rc3_1631614018 is Linux 5.0.0-beta64-rc3, build 1631614018.
var Linux_5_0_0_beta64_rc3_1631614018 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta64-rc3 [Build: 1631614018]",
	Sign:     "rtoVgZuDu9uXrV7xB8aSn5O+El99KxSvz6xwWzpN3mBG48dlLqbmmNGp61lkezyjXq+hgWhT28du6q9WDfduAQ==",
}

// Windows_5_0_0_beta64_1631702252 is Windows 5.0.0-beta64, build 1631702252.
var Windows_5_0_0_beta64_1631702252 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta64 [Build: 1631702252]",
	Sign:     "SsYcBVnP67XI5dKDbSOlWRns8968Y+V2DXeQUNhwKI69eyyB76eBrMgRTZ91rdgyQqaZCJKNiU1AIaPbV/XbAA==",
}

// MacOS_5_0_0_beta64_1631702252 is macOS 5.0.0-beta64, build 1631702252.
var MacOS_5_0_0_beta64_1631702252 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta64 [Build: 1631702252]",
	Sign:     "6JEBPkYHc1bs1KhrZaRzCHo4u871reAODdt1XVu/uGgMnj+tNLmL6dGJ6YaAuGG2leyFQ436PqRqRQVu7ZeCAw==",
}

// Windows_5_0_0_qa_66_1_1631885355 is Windows 5.0.0-qa-66-1, build 1631885355.
var Windows_5_0_0_qa_66_1_1631885355 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-66-1 [Build: 1631885355]",
	Sign:     "s+Lg/dUq3gTn1KbVtO3jC9KNhjVPKR5htkO+SIrGyaR/ToW7nr3KRE3PnF7P3tb/0wGIZ8JEz2Mta2hjSdIpCQ==",
}

// Windows_5_0_0_beta65_1632210487 is Windows 5.0.0-beta65, build 1632210487.
var Windows_5_0_0_beta65_1632210487 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta65 [Build: 1632210487]",
	Sign:     "CkKf8FYi9nWa5jRxOUQfvAy/2MYnSVE2Oaa2cOrOKYqRahpzUmsy14wwd0+ZSMLVqfG08EOpaVzeHr+7ySpqDQ==",
}

// Linux_5_0_0_beta65_1632210487 is Linux 5.0.0-beta65, build 1632210487.
var Linux_5_0_0_beta65_1632210487 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta65 [Build: 1632210487]",
	Sign:     "ChmllHZUolNrHhaBK+FHMfOBF4X56zaGeDMJ0qLzUZJz54UCuBiIEYiUhn02F6RKrBCM6fQ9I/MMzYOv0PdWAw==",
}

// Windows_5_0_0_beta65_1_rc1_1632234637 is Windows 5.0.0-beta65.1-rc1, build 1632234637.
var Windows_5_0_0_beta65_1_rc1_1632234637 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta65.1-rc1 [Build: 1632234637]",
	Sign:     "QYXj/5id/Kzjb+dbkRltV/ki7JpIRoJ2/nx7SNbXzC47XBT/iiQ5EiLI0F9G0g5V3UuGuepBnLyN7CeGrX0eBQ==",
}

// Windows_5_0_0_beta65_1_1632399768 is Windows 5.0.0-beta65.1, build 1632399768.
var Windows_5_0_0_beta65_1_1632399768 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta65.1 [Build: 1632399768]",
	Sign:     "pSqFVqZhNQVc1GcMzMV9MyynGj8wLNf/xW/QcymXtsGJO11dIqdgqhEIYrdadMyqnUhhMjNAMJeqcxop+pI9CQ==",
}

// Linux_5_0_0_beta65_1_1632399768 is Linux 5.0.0-beta65.1, build 1632399768.
var Linux_5_0_0_beta65_1_1632399768 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta65.1 [Build: 1632399768]",
	Sign:     "+wjy0tnkSfyxh/vRP7WqudF88ZPMjdcRC6MJWrtGbAJMBxbok1FP+3mUNyexlzcG1ZVCIv05LZ8CGAYzunNRCw==",
}

// MacOS_5_0_0_beta65_1_1632399768 is macOS 5.0.0-beta65.1, build 1632399768.
var MacOS_5_0_0_beta65_1_1632399768 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta65.1 [Build: 1632399768]",
	Sign:     "GsPT87agljBvFnlOSNWoNV6kLegxdYeKp/o0eeGLNV2e+4E0S+YE/eEAAS8kZK3F8b5rDR3MdvVx3W8QYxbwBA==",
}

// Windows_5_0_0_qa_66_4_1632410203 is Windows 5.0.0-qa-66-4, build 1632410203.
var Windows_5_0_0_qa_66_4_1632410203 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-66-4 [Build: 1632410203]",
	Sign:     "k+dlfbWu3GtyDXonTUkRK/qxEbl/Uuwo5ZWXDnIvKud3mSm2VX0VUyFzf5PGYoXpxkgJ1HtyOP/UhMqQ8uX5BQ==",
}

// Windows_5_0_0_ms_2_1632754860 is Windows 5.0.0-ms-2, build 1632754860.
var Windows_5_0_0_ms_2_1632754860 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ms-2 [Build: 1632754860]",
	Sign:     "/3SnS+0+R6/HruDLsfIs7d8IpfVMM9u013uTY9ImYpIXOFOINGMUUjTRhwA+oZPRaqEQf18uAZ93EzXOJbQ1BA==",
}

// Windows_5_0_0_qa_66_6_1633006583 is Windows 5.0.0-qa-66-6, build 1633006583.
var Windows_5_0_0_qa_66_6_1633006583 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-66-6 [Build: 1633006583]",
	Sign:     "p+DpdQ4Fi8tdnMvVP8jCS7IO33hVftvHZZD6v+szW3HzUJFA4Ueg5gz+lCaMcb5yZsPxDdIzS4QWV47KB3qcAg==",
}

// Windows_5_0_0_beta66_internal_1633604766 is Windows 5.0.0-beta66-internal, build 1633604766.
var Windows_5_0_0_beta66_internal_1633604766 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta66-internal [Build: 1633604766]",
	Sign:     "PGkf4H8G/y5n19h1JmwUZpDt07U+BjdXurYzaUyGqW5J0bdZSVJlR5teIb690XAFGdyFX6R15e3bH1XqXQXRDA==",
}

// Windows_5_0_0_beta66_rc1_1634917358 is Windows 5.0.0-beta66-rc1, build 1634917358.
var Windows_5_0_0_beta66_rc1_1634917358 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta66-rc1 [Build: 1634917358]",
	Sign:     "f0+4Ff3AmbkzP1J2fQmgdp3WwaYJ0A5UcMGKG+ze+PxhNMEWAdM0XzixD9wj6lDR2XiOzVR1i2Q/tFVv8Nj8AQ==",
}

// Linux_5_0_0_beta66_rc1_1634917358 is Linux 5.0.0-beta66-rc1, build 1634917358.
var Linux_5_0_0_beta66_rc1_1634917358 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta66-rc1 [Build: 1634917358]",
	Sign:     "rVTAulwEQD1FGNG753/mCrbMxZyG0ZBYBt8vkJiJYcGO+y6Q09/y059jMxqXAARspIDUNhEgoIUt/jnYNZFXBw==",
}

// Windows_5_0_0_beta66_1635340287 is Windows 5.0.0-beta66, build 1635340287.
var Windows_5_0_0_beta66_1635340287 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta66 [Build: 1635340287]",
	Sign:     "81WF3pCS63ISYJOQX+OXXxITSQjd0pu/Ofpp1cZu3E9VWoMimP1YUCaSBq7kAeZwcNrbVJJ4C6sUJEIDx3Y0Dg==",
}

// Linux_5_0_0_beta66_1635340287 is Linux 5.0.0-beta66, build 1635340287.
var Linux_5_0_0_beta66_1635340287 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta66 [Build: 1635340287]",
	Sign:     "KIEvK+JNGlzOIN4wzetVEEpr1/Gsy035+kRP4uUANv6efNYe06yTDHqwk13GDCu2Z03dO8XBs/ZVMhDIEdWQCA==",
}

// MacOS_5_0_0_beta66_1635340287 is macOS 5.0.0-beta66, build 1635340287.
var MacOS_5_0_0_beta66_1635340287 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta66 [Build: 1635340287]",
	Sign:     "FNlzmJhKg0RKPI5GpYR0ZVZlxcFtYpAd20mCBVv1XKzGyR+kaccsaQhecq3aclEgKHziHMDolS892C2hOcYyDw==",
}

// Windows_5_0_0_beta67_rc1_1635512518 is Windows 5.0.0-beta67-rc1, build 1635512518.
var Windows_5_0_0_beta67_rc1_1635512518 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta67-rc1 [Build: 1635512518]",
	Sign:     "e6F3H0g2IlMkeMCJyNZYgMFW1OSRRC1SF5uWN+gx1zghfUWUtp08zux9tH2ySBl1e5YyWIP8mOBXgxwFJgvdDA==",
}

// Linux_5_0_0_beta67_rc1_1635512518 is Linux 5.0.0-beta67-rc1, build 1635512518.
var Linux_5_0_0_beta67_rc1_1635512518 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta67-rc1 [Build: 1635512518]",
	Sign:     "Lz6odZRsICbIOwjBalAYBU2fwc+raJDgPi7XM620u7C1A/+OoGKuxMthkOWZ/JW9dlnYs7d7Z8QyLop3Qa2uCA==",
}

// Windows_5_0_0_beta67_rc2_1636124060 is Windows 5.0.0-beta67-rc2, build 1636124060.
var Windows_5_0_0_beta67_rc2_1636124060 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta67-rc2 [Build: 1636124060]",
	Sign:     "prboyJmD3J7qhFJ2/tnLxVk2Uf0moxggtCLZyEpUHhJiKiDKR6QdeTx5K4u2TwBuvK0tFtvj058Z85s219DMCA==",
}

// Linux_5_0_0_beta67_rc2_1636124060 is Linux 5.0.0-beta67-rc2, build 1636124060.
var Linux_5_0_0_beta67_rc2_1636124060 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta67-rc2 [Build: 1636124060]",
	Sign:     "4ERq1ihEy1ArHecbrYZfnQMvHFrInBYYsZnmMupkdpoDaRiviSbVlTXY5U1q9njYrzsj8s4EI8c2A6x0PV46Cg==",
}

// MacOS_5_0_0_beta67_rc2_1636124060 is macOS 5.0.0-beta67-rc2, build 1636124060.
var MacOS_5_0_0_beta67_rc2_1636124060 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta67-rc2 [Build: 1636124060]",
	Sign:     "P0Iy6rBbnsYHOVt7y7/nbepH0eoopP8PzLc6JMvqOUE+uoInlQmRcy3mTfNyaQSBgZ2NTqw2NFbBP7Kv+h9QAA==",
}

// Windows_5_0_0_beta67_rc3_1636470636 is Windows 5.0.0-beta67-rc3, build 1636470636.
var Windows_5_0_0_beta67_rc3_1636470636 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta67-rc3 [Build: 1636470636]",
	Sign:     "dXRBa//M5qWE64qfdGybN84JnOLbMrCJIReuv2c6eViWtjyE5AcLVE7X21DW5MtMGXeXZB/qwxbBzPHKErxrBQ==",
}

// Linux_5_0_0_beta67_rc3_1636470636 is Linux 5.0.0-beta67-rc3, build 1636470636.
var Linux_5_0_0_beta67_rc3_1636470636 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta67-rc3 [Build: 1636470636]",
	Sign:     "cS+PB8d4YtslCr9Z3jlNfNhuSdqbUfufnn9wbbDl2/h4Drb3okxvRS+2pDjZASYGkOC3Gf+VUkGmZsrDg5ftCw==",
}

// Windows_5_0_0_beta67_rc4_1636703696 is Windows 5.0.0-beta67-rc4, build 1636703696.
var Windows_5_0_0_beta67_rc4_1636703696 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta67-rc4 [Build: 1636703696]",
	Sign:     "2wcKHWrzsPtLLv4QZTTfKZCc8narFgsSTlq7z9w8egpfx4jt4Y0ZLQV8usasdO4AaklKY/Y4072tJiTcP3XFCQ==",
}

// Linux_5_0_0_beta67_rc4_1636703696 is Linux 5.0.0-beta67-rc4, build 1636703696.
var Linux_5_0_0_beta67_rc4_1636703696 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta67-rc4 [Build: 1636703696]",
	Sign:     "sLNPLyXWN9w+p4qhmmWJeYy2qiD1GYpBUuJVY9BYuzM6Znm56zpseQqFCvS43of5B2zb5DsCgm87WWx/+3kOBg==",
}

// Windows_5_0_0_beta67_rc5_1637773695 is Windows 5.0.0-beta67-rc5, build 1637773695.
var Windows_5_0_0_beta67_rc5_1637773695 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta67-rc5 [Build: 1637773695]",
	Sign:     "IRTxy8FOruwU0CtxGzE/ix3zE8IBztKfdcjy21C5kScKp1Ne/r8NpOF8r4H1PYX/FQw0PVkQY+/8kK4uVXS+CA==",
}

// Linux_5_0_0_beta67_rc5_1637773695 is Linux 5.0.0-beta67-rc5, build 1637773695.
var Linux_5_0_0_beta67_rc5_1637773695 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta67-rc5 [Build: 1637773695]",
	Sign:     "G9yoF9j+CgxEDcDpFJjxtokCXYQxxPuMwFKHuceK/p2xtae6CufhkZh5ebCYKHHqOzLJ8SshC8IlAn8QQgRmBA==",
}

// Windows_5_0_0_olm_refactor_1_1638283086 is Windows 5.0.0-olm-refactor-1, build 1638283086.
var Windows_5_0_0_olm_refactor_1_1638283086 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-olm-refactor-1 [Build: 1638283086]",
	Sign:     "uUXlxNlsH6NampO9EAjYT1r0/yKZPyaGtP986lv1JMGsMq3sPz4OEqCjyG0p+eJT2sLx8N7pXoiFw6K0e4lRBw==",
}

// Windows_5_0_0_beta67_1638359901 is Windows 5.0.0-beta67, build 1638359901.
var Windows_5_0_0_beta67_1638359901 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta67 [Build: 1638359901]",
	Sign:     "nlVdu01SISGsf7cPVeYc+1kTHhEsnD1sZtaqeZaMKUpPFCAreuDsZ3ECqm+DbVg7C3ZbKcxszlVwVxwroBOADQ==",
}

// Linux_5_0_0_beta67_1638359901 is Linux 5.0.0-beta67, build 1638359901.
var Linux_5_0_0_beta67_1638359901 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta67 [Build: 1638359901]",
	Sign:     "oywbpFbPkRymBLBhZM1a1LPY+6oAtqA807kBF0EyB5rpEsqulMXJzTlECjVf4eiWHLTGL/VkpyLy+3yjcTMfCA==",
}

// MacOS_5_0_0_beta67_1638359901 is macOS 5.0.0-beta67, build 1638359901.
var MacOS_5_0_0_beta67_1638359901 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta67 [Build: 1638359901]",
	Sign:     "P8sgAyL2yCinMHqSJ3chgCRS4D5rN9TvAyuloSeildT9lEivLK+5mxvAWndFn8uOvf8bZTDi+TxSmfAzQ/NVDg==",
}

// MacOS_5_0_0_qa_68_2_1638544382 is macOS 5.0.0-qa-68-2, build 1638544382.
var MacOS_5_0_0_qa_68_2_1638544382 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-qa-68-2 [Build: 1638544382]",
	Sign:     "G9sFGBu0WBzKRAlGGeVJM0bOzUSsHiEZb35cVTfcvt1xtsNtsRsnw9sMuweDGuB26gzE7ajuYEdBX2FbMRwyDg==",
}

// Windows_5_0_0_qa_store_update_dummy_fix_1_1639400688 is Windows 5.0.0-qa-store-update-dummy-fix-1, build 1639400688.
var Windows_5_0_0_qa_store_update_dummy_fix_1_1639400688 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-store-update-dummy-fix-1 [Build: 1639400688]",
	Sign:     "SlypMzSvf7FKTZceC2SgvNaZ9fOEZu2cV7mQr6Hf1CVSAKRXZkmlucUvKlqyU9Rj/2s8RZoLwiYrKjMLwILYDg==",
}

// Windows_5_0_0_qa_store_update_dummy_fix_2_1639646105 is Windows 5.0.0-qa-store-update-dummy-fix-2, build 1639646105.
var Windows_5_0_0_qa_store_update_dummy_fix_2_1639646105 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-store-update-dummy-fix-2 [Build: 1639646105]",
	Sign:     "wUm+ktQaSeaEYWwV20nSPC4ZPERsA57UeCJx8BJYTxiEGCKEYdBZrsAm+jIrwwtrO4KD/k3ICO0xS9jzQX1YAw==",
}

// Windows_5_0_0_qa_th_16_1640003749 is Windows 5.0.0-qa-th-16, build 1640003749.
var Windows_5_0_0_qa_th_16_1640003749 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-th-16 [Build: 1640003749]",
	Sign:     "bjPYVLTJYZk2Ssn3yrNftHm9azsSAajfr9VLP+RAWueV4AN3gqIq3wg6htQu4AJkjY59cJZAOEdfrpF8C6k7CA==",
}

// IOS_3_6_0_1640259570 is iOS 3.6.0, build 1640259570.
var IOS_3_6_0_1640259570 = ClientVersion{
	Platform: "iOS",
	Version:  "3.6.0 [Build: 1640259570]",
	Sign:     "4Bk+MYCta3b2SlKl7cVMrRgNTCOGv4qPOVpQ84c3ueaDrOzXcI0REIjLJ/Pcp9jhIJ+Jb1ODZBT8dZxbm2w4Ag==",
}

// Windows_5_0_0_qa_68_7_1642008173 is Windows 5.0.0-qa-68-7, build 1642008173.
var Windows_5_0_0_qa_68_7_1642008173 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-68-7 [Build: 1642008173]",
	Sign:     "lBXxbwIGhA065UoLqw7or4St5qssnkFb4Nw0B01OLNdPxGvGiWgBd4G9Q7J1EnX86g7KqLYRY8PPbiP6jr1BAw==",
}

// Windows_5_0_0_qa_68_9_1642074370 is Windows 5.0.0-qa-68-9, build 1642074370.
var Windows_5_0_0_qa_68_9_1642074370 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-68-9 [Build: 1642074370]",
	Sign:     "HaUTRwyKMGRUAK1SJcnCy8sPXh3bx8qi+LsKuN9bPVfV1R7eMymV2Zx5BUVbsLJxINxJZ23bWUH0eejtIgQgAg==",
}

// Windows_5_0_0_qa_68_10_1642155836 is Windows 5.0.0-qa-68-10, build 1642155836.
var Windows_5_0_0_qa_68_10_1642155836 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-68-10 [Build: 1642155836]",
	Sign:     "Q68Iwg2vo/mfH078GGj2OzRIXiucddLud1txjNkH2ptxDvAfClENMBKjLpfoEtoiZm5XYwIxeyTskNc9C3YOBg==",
}

// Windows_5_0_0_qa_68_11_1642428288 is Windows 5.0.0-qa-68-11, build 1642428288.
var Windows_5_0_0_qa_68_11_1642428288 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-68-11 [Build: 1642428288]",
	Sign:     "QyavWsP9ouGPX1I36sB3aWXbT2d8OwZRUDoHkY8OBNvJbGiTXfOrVrvR4LD+bgvsc+VuOVlSjx0II4pk8GljAQ==",
}

// Windows_5_0_0_beta68_rc1_1642505026 is Windows 5.0.0-beta68-rc1, build 1642505026.
var Windows_5_0_0_beta68_rc1_1642505026 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta68-rc1 [Build: 1642505026]",
	Sign:     "EwORWPWSYjN1l3RGQFWFcJ+fBCcFj8yHW40nb9srtQZ1iLic1qfPiKF+7jzNLHJS1iS6Qx7UuBqONZLSz0X8CQ==",
}

// Linux_5_0_0_beta68_rc1_1642505026 is Linux 5.0.0-beta68-rc1, build 1642505026.
var Linux_5_0_0_beta68_rc1_1642505026 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta68-rc1 [Build: 1642505026]",
	Sign:     "qR7e88rbZLNH138DTrg91DtKoOCnsQ7yTgmVBXlc7WoIuJ2nd7Ucjn00AzM9GM6SZkfFvF3D0HynflxcxA4hCw==",
}

// Windows_5_0_0_beta68_rc2_1642605878 is Windows 5.0.0-beta68-rc2, build 1642605878.
var Windows_5_0_0_beta68_rc2_1642605878 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta68-rc2 [Build: 1642605878]",
	Sign:     "4yPatak9NIsDMyCODgDOuaQNO08poDm9+qDgd58GC7wsvtxt99iT26gZ5YmNS8vYk5GdfQCZEy2QzfMRs0FDDg==",
}

// Linux_5_0_0_beta68_rc2_1642605878 is Linux 5.0.0-beta68-rc2, build 1642605878.
var Linux_5_0_0_beta68_rc2_1642605878 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta68-rc2 [Build: 1642605878]",
	Sign:     "UfX2E2kPPWRGRrTzEbKJDwRVOh5HEFX8pg4vjxwA05hn7F5xEXb7+b0yucRD10pQBq3G/jHqVfJ1RlvKNNO+Dg==",
}

// Windows_3_6_0_1642760631 is Windows 3.6.0, build 1642760631.
var Windows_3_6_0_1642760631 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1642760631]",
	Sign:     "YtVPmw3A0aPfTqOU8OyQVoDuKtPBCtiFrJgA1oajXRLchnKBYSCiK2K6Q/mQs+cn7cmVp1ZV0+aYGvUJRQLNCA==",
}

// Windows_5_0_0_qa_68_20_1642762634 is Windows 5.0.0-qa-68-20, build 1642762634.
var Windows_5_0_0_qa_68_20_1642762634 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-68-20 [Build: 1642762634]",
	Sign:     "Sx7RQEHiEnKpD/CGZ2V9StXKVWrsvgDePlkUvBhd1VcQnkQ8ShPauJGHic1MiAIv4+9VKCuF2dMuOUmzjJTZAw==",
}

// Windows_5_0_0_beta68_rc3_1643385351 is Windows 5.0.0-beta68-rc3, build 1643385351.
var Windows_5_0_0_beta68_rc3_1643385351 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta68-rc3 [Build: 1643385351]",
	Sign:     "G5+2JSGlehLUwn5DzNDL9/8zDGmSdHAY7Cg930aOeufmUyJmXgpzS87hkhaMAByDArp+Td+WLTkJxn2wE1HrAg==",
}

// Linux_5_0_0_beta68_rc3_1643385351 is Linux 5.0.0-beta68-rc3, build 1643385351.
var Linux_5_0_0_beta68_rc3_1643385351 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta68-rc3 [Build: 1643385351]",
	Sign:     "DHKCUoEm36bI1t7wBpq+ju0HyVXUp2eRgjV58n2C5a8kAHDz/jgiZzKSJeLPx0bZuAd10Gv2pNqEeb5UkVbIBA==",
}

// Windows_5_0_0_qa_68_26_1643637044 is Windows 5.0.0-qa-68-26, build 1643637044.
var Windows_5_0_0_qa_68_26_1643637044 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-68-26 [Build: 1643637044]",
	Sign:     "WNcgfD6kvSXSzUeQaxVxIiX0e+xv/rKBdqSm/ORXeimArty2EoCA5sm65xpcy0FHOG5BciX9JJjvkSIdB76gDg==",
}

// Windows_5_0_0_qa_68_27_1643641086 is Windows 5.0.0-qa-68-27, build 1643641086.
var Windows_5_0_0_qa_68_27_1643641086 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-68-27 [Build: 1643641086]",
	Sign:     "hTifgq7hQ1G9S/ULyEr2NHSteil5T9KC8w65e+UwWkJqhHSWgaA0ICUOSB5J9/yd0alFJU/6XpjoqSFW5WTwCA==",
}

// Windows_5_0_0_beta68_1643723246 is Windows 5.0.0-beta68, build 1643723246.
var Windows_5_0_0_beta68_1643723246 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta68 [Build: 1643723246]",
	Sign:     "CW57oWrfk7qPSrRifg+pNIUoFGl/7fjoCcEClJqRRNtAK0CjCnx99/auvO3BSB9rPRRWq41C6q9VuhVugKP9Ag==",
}

// MacOS_5_0_0_beta68_1643723246 is macOS 5.0.0-beta68, build 1643723246.
var MacOS_5_0_0_beta68_1643723246 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta68 [Build: 1643723246]",
	Sign:     "hnLrqXS21edeNiHiaU2V/Q8TGloQKp9dxh1Of+NiLEJB1koDfY1bW9H31oVLrSSH8U35kC3WnIdcb/J7h2/mDA==",
}

// Windows_5_0_0_beta68_1_1643727795 is Windows 5.0.0-beta68.1, build 1643727795.
var Windows_5_0_0_beta68_1_1643727795 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta68.1 [Build: 1643727795]",
	Sign:     "jDTnopWRErSf1sO1vH6Yx1qxZPNv7hwZFQRvFdeqe9Z4hQHrY4Mgt7lhHDG7Q2H3ss7wZ0D8H12CnXC5RNB5DQ==",
}

// Windows_5_0_0_qa_69_5_1643982067 is Windows 5.0.0-qa-69-5, build 1643982067.
var Windows_5_0_0_qa_69_5_1643982067 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-5 [Build: 1643982067]",
	Sign:     "UyXxYq75NUY2oTdYgKFBj/FrXjbVVgzO7ly0CBIswihoyUm5UiBiUMZ3TVIparJA9JOnuleiDkih3fhXQRiEBw==",
}

// Windows_5_0_0_qa_69_6_1644241206 is Windows 5.0.0-qa-69-6, build 1644241206.
var Windows_5_0_0_qa_69_6_1644241206 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-6 [Build: 1644241206]",
	Sign:     "0P04q5dEPdCWHifYv7HSlrRWM08LeiQ09+1D8U6kU9gzf1cHJXw+5+FRG6dNb3dzzS6sQnTZtsVjbAF4h5uvCg==",
}

// Windows_5_0_0_beta68_1_1644243684 is Windows 5.0.0-beta68.1, build 1644243684.
var Windows_5_0_0_beta68_1_1644243684 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta68.1 [Build: 1644243684]",
	Sign:     "vONV07+8AMY7TPSRMH0PB79b1b6jY30cMoS6X29yfSp0U/S8eNTyfXz9fHrUhqdzm2jcfYSrWNCjjMIfGPq1Aw==",
}

// Linux_5_0_0_beta68_1_1644243684 is Linux 5.0.0-beta68.1, build 1644243684.
var Linux_5_0_0_beta68_1_1644243684 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta68.1 [Build: 1644243684]",
	Sign:     "cDEN9t3q4YMtjOQ6a4Yp+7YnsdxDE/1lfhqFjSBUrpoyEqKarLkqGLgNop3vJ59trCSzqJzXskIHFWXtggZtCg==",
}

// MacOS_5_0_0_beta68_1_1644243684 is macOS 5.0.0-beta68.1, build 1644243684.
var MacOS_5_0_0_beta68_1_1644243684 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta68.1 [Build: 1644243684]",
	Sign:     "1EiWEK4KR4b4/odYwBhIy1b9dSj0ffNkN23RJUDem2JCFVSOExCkVx98HEH/OhO+OzThC43LX4++0eGvoDYkDQ==",
}

// Windows_5_0_0_beta69_rc1_1644575557 is Windows 5.0.0-beta69-rc1, build 1644575557.
var Windows_5_0_0_beta69_rc1_1644575557 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69-rc1 [Build: 1644575557]",
	Sign:     "mgxRbc8omXUpB2Zxs7oZfL7ocjuSlcUTH+lV0RY60rY2LLIdmLsitPDYQbMkzMSdIwCMGhmKWJPUN3LaSy4LCw==",
}

// Windows_5_0_0_beta69_rc2_1644595314 is Windows 5.0.0-beta69-rc2, build 1644595314.
var Windows_5_0_0_beta69_rc2_1644595314 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69-rc2 [Build: 1644595314]",
	Sign:     "NaJjYxfhehKp7xp3cRHdFFL4fl4LKuvMEL55y+6SvBwfIsjVx6MFCUNgAqc39ZPsGQbCXNa7d8Ik/wmyrBQAAQ==",
}

// Linux_5_0_0_beta69_rc2_1644595314 is Linux 5.0.0-beta69-rc2, build 1644595314.
var Linux_5_0_0_beta69_rc2_1644595314 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta69-rc2 [Build: 1644595314]",
	Sign:     "TOhCAXR02A4yFiLwABZARKrnamhVM5mLhmL8aV6tzyFlfaHwUbuHYcIPkaewSyaOCEgD8i3spZ/+XqS+4n6pAA==",
}

// Windows_5_0_0_beta69_rc3_1644660819 is Windows 5.0.0-beta69-rc3, build 1644660819.
var Windows_5_0_0_beta69_rc3_1644660819 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69-rc3 [Build: 1644660819]",
	Sign:     "GB3DbCn/JEGuDJ6jdafCkzIl6u4O5zDWsUdQUfGyPMRtjF/63foso4f49B0sqsaJUIXe5wpgQC5LGqVOsGOADw==",
}

// Linux_5_0_0_beta69_rc3_1644660819 is Linux 5.0.0-beta69-rc3, build 1644660819.
var Linux_5_0_0_beta69_rc3_1644660819 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta69-rc3 [Build: 1644660819]",
	Sign:     "p/nRODqs/OFcPMhstqmAvft79CLf1Cgnn6NAslbf6NGPWZykMI98FLeblPR09k+PoeXi0hj78v41qRGVFPIABg==",
}

// Windows_5_0_0_beta69_rc4_1645087682 is Windows 5.0.0-beta69-rc4, build 1645087682.
var Windows_5_0_0_beta69_rc4_1645087682 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69-rc4 [Build: 1645087682]",
	Sign:     "NqR1eiD/HyG4Z6/OdTMdkKdA6SnjHkvx4ZPt/wVMdD0lTL3QMpkxkl3/iHvb4ZmZaUFnsZUiWgoG/tWorkDgBQ==",
}

// Linux_5_0_0_beta69_rc4_1645087682 is Linux 5.0.0-beta69-rc4, build 1645087682.
var Linux_5_0_0_beta69_rc4_1645087682 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta69-rc4 [Build: 1645087682]",
	Sign:     "smuuiUwigzbiDd6+qu27VH9mm7PzuTmOlec4rsqND2Y9RDrZewkl15Svx7ZFApXZGYPdMOfRnnXX6Un1Tph/Cw==",
}

// Android_5_0_0_1645113667 is Android 5.0.0, build 1645113667.
var Android_5_0_0_1645113667 = ClientVersion{
	Platform: "Android",
	Version:  "5.0.0 [Build: 1645113667]",
	Sign:     "z2LG+Ab8slNy0covF7NttNzwHPhF14hu+EMkDZwjIsdvU2BU4bTXjtkI2gjow/N/p/ba42SE9MLTiFglXuThBg==",
}

// Windows_5_0_0_beta69_rc5_1645448271 is Windows 5.0.0-beta69-rc5, build 1645448271.
var Windows_5_0_0_beta69_rc5_1645448271 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69-rc5 [Build: 1645448271]",
	Sign:     "9rCNmBrEhBaX2bzyrW9kx2S8umP6AELtt11uPclBC2DNaOW2aSUJSA3LkZ1m7Fu0TPeD908+XXDnWlsHvRUYCg==",
}

// Windows_5_0_0_beta69_rc6_1645527496 is Windows 5.0.0-beta69-rc6, build 1645527496.
var Windows_5_0_0_beta69_rc6_1645527496 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69-rc6 [Build: 1645527496]",
	Sign:     "/clk64cVjel/kF3YlDgiWAJkN7PkFrjHKyMCK9tfcxeV/+08Fot14sXLSaW1B36qo9qFF/kUUZGt/Ku+eZn3Cw==",
}

// Linux_5_0_0_beta69_rc6_1645527496 is Linux 5.0.0-beta69-rc6, build 1645527496.
var Linux_5_0_0_beta69_rc6_1645527496 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta69-rc6 [Build: 1645527496]",
	Sign:     "4NIKPJar37y8+PnVe/mTc4xluPyi4gSXvK5ZWku0epo2XgQuJ0+AoMDmWVTyfNue/VupYBUdzEfiDifxYc6BBA==",
}

// Windows_5_0_0_qa_69_12_1645630715 is Windows 5.0.0-qa-69-12, build 1645630715.
var Windows_5_0_0_qa_69_12_1645630715 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-12 [Build: 1645630715]",
	Sign:     "UnIsz7yDLr3lnzt2pYKAZNC1g8oLqv3ekuTqskM0ZGeso0Y7GhhDMZARCFrJMWVDccA+fzpMI25PoPD7KfCoDA==",
}

// Windows_5_0_0_qa_69_14_1646064573 is Windows 5.0.0-qa-69-14, build 1646064573.
var Windows_5_0_0_qa_69_14_1646064573 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-14 [Build: 1646064573]",
	Sign:     "DHlU9hofr22th7vP0Kii0bnJpVf8yh56ctIPD8U4l1IKY+Yc2a1cw2Mw3q0fT0e73W4uskbgUkhUflSW4QHDBQ==",
}

// Windows_5_0_0_qa_69_15_1646165194 is Windows 5.0.0-qa-69-15, build 1646165194.
var Windows_5_0_0_qa_69_15_1646165194 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-15 [Build: 1646165194]",
	Sign:     "Hev8vdybbsX2FIMW/aXpfbmYJGg0pgYi0nLHxeMk5i7su+dcVNKAXByM4+De8wcJEQ+nO5klrtA/B1HayyJABA==",
}

// Windows_5_0_0_qa_69_16_1646319264 is Windows 5.0.0-qa-69-16, build 1646319264.
var Windows_5_0_0_qa_69_16_1646319264 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-16 [Build: 1646319264]",
	Sign:     "S7EflYS+8UCKLTYgWFM+pjDy61/4E04kqRevUmIEu1sKhbOVpAWlawVboUUybjoGOaCxauMFnjablj4Q5NpYBw==",
}

// Windows_5_0_0_qa_69_18_1646666161 is Windows 5.0.0-qa-69-18, build 1646666161.
var Windows_5_0_0_qa_69_18_1646666161 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-18 [Build: 1646666161]",
	Sign:     "TjHJin1ghKvzLubbMJXy6ePCPcX2tnVlVzS2cZYcT/gx2uYSQVLhZxF1pHHC0ZgOcF+HIUgmY0UbU+oj4JikAA==",
}

// Windows_5_0_0_qa_69_20_1646829751 is Windows 5.0.0-qa-69-20, build 1646829751.
var Windows_5_0_0_qa_69_20_1646829751 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-20 [Build: 1646829751]",
	Sign:     "NpmWEkUZ1rW5jSnCktzCnU/7A+uaUBQ0b9oyo8IRgOihNQL2i1CsEPgssj0auVU86lx/1SS15CI4uNjOhRMfAw==",
}

// Windows_5_0_0_qa_request_chat_7_1646854452 is Windows 5.0.0-qa-request-chat-7, build 1646854452.
var Windows_5_0_0_qa_request_chat_7_1646854452 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-request-chat-7 [Build: 1646854452]",
	Sign:     "0iRGPzh37MelxPeKE15K754jAi+yXJ2bu+pXV1ErOFbEF504WtUZaAIoFVHBNheIVdSCrxuWFF17xG1w2gSICQ==",
}

// Windows_5_0_0_qa_69_21_1646935163 is Windows 5.0.0-qa-69-21, build 1646935163.
var Windows_5_0_0_qa_69_21_1646935163 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-21 [Build: 1646935163]",
	Sign:     "06E3t4+OxXNtYQMQO7p87FnjUFzsiRyBG41nbdoavLuAz9aPmMG1Hu865qRfAXIUioQgVlLY0nJj8vdZtntqCw==",
}

// Windows_5_0_0_t_2915_2_1647254017 is Windows 5.0.0-t-2915-2, build 1647254017.
var Windows_5_0_0_t_2915_2_1647254017 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-t-2915-2 [Build: 1647254017]",
	Sign:     "1mnBwJhwdrkWBtHRePQtlYRjFmGnQmyglqRrtsmTb9sj6guDUY4Aw/i98feAP7O1hZO461QvAgtNfXmMq015Cw==",
}

// Windows_3_6_0_1647511767 is Windows 3.6.0, build 1647511767.
var Windows_3_6_0_1647511767 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647511767]",
	Sign:     "S9Ow15joaTizvIJ4xTf1FYpkn9jHIzO+ShPU9Va/g9UsF70+LfEQBgneDx0llRzzbIglcXAQOvm3VKOPTVASDw==",
}

// Windows_3_6_0_1647530723 is Windows 3.6.0, build 1647530723.
var Windows_3_6_0_1647530723 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647530723]",
	Sign:     "cwRrfUAx3jpu2AC7UmX2z5PrjSEijHFVmwoh8W+6y8mmxHQMu6CJvrr2Mf/OCNmGor82fCjWqXwLSK2McVx3Cw==",
}

// Windows_3_6_0_1647595742 is Windows 3.6.0, build 1647595742.
var Windows_3_6_0_1647595742 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647595742]",
	Sign:     "MVrkchf+oadHXHVZGRrY/WYg2QH45rdt2MRgZ+0UA6c15L2P+05u/5YiG+4Zp82XLsv2xZYSuM99xcOoLxaqDQ==",
}

// Linux_3_6_0_1647595742 is Linux 3.6.0, build 1647595742.
var Linux_3_6_0_1647595742 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1647595742]",
	Sign:     "jyIo8JaV2sSEeilGEIGEdjm7q5zA6GT6kZH0QcbtJNzuzgjQ8FwSbJnOY5crSys9zdQNIEaaUrZliJowClUnBw==",
}

// Windows_3_6_0_1647855949 is Windows 3.6.0, build 1647855949.
var Windows_3_6_0_1647855949 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647855949]",
	Sign:     "xPqml2CxNFCbEI+ZcyCcIP8CrK7S+IT4I2f8DyY41UIae6WX+wujSflbGXWrzssEmsYh5vLoSn1b2TmHyIdPAQ==",
}

// Linux_3_6_0_1647855949 is Linux 3.6.0, build 1647855949.
var Linux_3_6_0_1647855949 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1647855949]",
	Sign:     "z1lAocn2kKnQ24Pt5pOzfRx6Tp+vKSxdb7BINN7zYaWceYi2cnugGMBGzqN6MkStI0ROHx7RCpBqRWKub+YaAg==",
}

// Windows_3_6_0_1647921962 is Windows 3.6.0, build 1647921962.
var Windows_3_6_0_1647921962 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647921962]",
	Sign:     "gx/meu4ewDSqByAxHDJ8ordqoUyqC/lQEeV0NzgWZvAtQScqDGCEOtNzDly0zKfRQ3HBidT4EUJcLZIxIho2Cw==",
}

// Windows_3_6_0_1647928456 is Windows 3.6.0, build 1647928456.
var Windows_3_6_0_1647928456 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647928456]",
	Sign:     "redEKXeLBo6GOtHjP5Rd/A8zadfkQe8kk6eM5EawvWHpShAB/xRWtNuZPuJzZQbhO+cytH/CM68huBUCgKN5DA==",
}

// Windows_3_6_0_1647939487 is Windows 3.6.0, build 1647939487.
var Windows_3_6_0_1647939487 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647939487]",
	Sign:     "dN1D99vIPuicNDyZfcy//Pm+IZpvRZtE7eaB2oPuj3UuMt4zSTlZY83gNwysucxzNLPTnFIWgGG1HXzaceyRCA==",
}

// Windows_3_6_0_1647949292 is Windows 3.6.0, build 1647949292.
var Windows_3_6_0_1647949292 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1647949292]",
	Sign:     "kQ/P5bPJ2ier+LCRZOmnNeD0WKmFrLT9g3gth/Jv+EE0cBliQB1t11uxV1nclPWVsVIVIxQlyvl7ryV/cMJDDA==",
}

// MacOS_3_6_0_1647949292 is macOS 3.6.0, build 1647949292.
var MacOS_3_6_0_1647949292 = ClientVersion{
	Platform: "macOS",
	Version:  "3.6.0 [Build: 1647949292]",
	Sign:     "0U/IWJ1DttzwFIzBp3R7xfNJZsaOFDx6iBLo/A5SevQLE6FsAIfY2OpQe+qi3fFjMF7pp56l+fdR8UB6wgSBDQ==",
}

// Windows_5_0_0_qa_69_26_1648062270 is Windows 5.0.0-qa-69-26, build 1648062270.
var Windows_5_0_0_qa_69_26_1648062270 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-26 [Build: 1648062270]",
	Sign:     "Mgd0GL5Ui6UiGQN0nSTkDy8d5fxqRKtohpazQWJrycewP4D8/iOafBpaBn5tKacy0nc6Q7Zbx9+MSnwdilP/DQ==",
}

// Windows_3_6_0_1648153885 is Windows 3.6.0, build 1648153885.
var Windows_3_6_0_1648153885 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1648153885]",
	Sign:     "j3B9t27eIoSbAiLqV4YwLoPIeIp1Hq1lNKpArE1MI1LPtkLF9llUAERFtkhcQH7Ofxld2jPnVphYYcfkcPZyDg==",
}

// Linux_3_6_0_1648153885 is Linux 3.6.0, build 1648153885.
var Linux_3_6_0_1648153885 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1648153885]",
	Sign:     "cjqAPjXF/Nk3PVVcns8aKSJoVLkSe2Y+1gxMiUCsG8ZEOi2tixm7HDfLCrBwfxuwD6LOOPaaANnjeb5Q/GSPCA==",
}

// MacOS_3_6_0_1648153885 is macOS 3.6.0, build 1648153885.
var MacOS_3_6_0_1648153885 = ClientVersion{
	Platform: "macOS",
	Version:  "3.6.0 [Build: 1648153885]",
	Sign:     "Gcb6nEkVgdA0jyqR1O5xYWNHL4LLJw8al++hABOFmO4gUbuTL4iVUD5tOsSLAVdpKKcjDlBoA8i+d2WFMWWMBw==",
}

// Windows_5_0_0_qa_69_27_1648222308 is Windows 5.0.0-qa-69-27, build 1648222308.
var Windows_5_0_0_qa_69_27_1648222308 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-27 [Build: 1648222308]",
	Sign:     "aztxNBrsEXa2jMs1rQzl0RQjFsdZgfU9jBGXRKAwxm+gigqm2hsGkDZbwasCR1evWEekf4Oo/guXlCkbg4BQCA==",
}

// Windows_5_0_0_qa_69_28_1648740980 is Windows 5.0.0-qa-69-28, build 1648740980.
var Windows_5_0_0_qa_69_28_1648740980 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-28 [Build: 1648740980]",
	Sign:     "yjCmepdVF4RRCBVDcq1dcLe4pmFAxAbIoZoqHWlAXZjy9OMUrW3dqqs5u4BsbJOAA9/WJ+5apc85umalkEmAAw==",
}

// Windows_5_0_0_qa_69_29_1649081557 is Windows 5.0.0-qa-69-29, build 1649081557.
var Windows_5_0_0_qa_69_29_1649081557 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-29 [Build: 1649081557]",
	Sign:     "AbKy5mV7Xwtt7V7QWeXRPoTomTeK74zmx7XdQ1o+mnRDNig6Yi6HzYMRUoAj0kzRxLFke7ASg8mjWNLjP7CZCA==",
}

// Windows_5_0_0_qa_69_30_1649229901 is Windows 5.0.0-qa-69-30, build 1649229901.
var Windows_5_0_0_qa_69_30_1649229901 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-30 [Build: 1649229901]",
	Sign:     "jsY5tIebotP8ZhB1ZCCd3GYhbP/P2RnhObM2VQEElO/5mMOgnvofcDkvhWbPDKbhvq0cIXBjix4PzR2nrO8WDg==",
}

// Windows_5_0_0_beta69_rc8_1650464356 is Windows 5.0.0-beta69-rc8, build 1650464356.
var Windows_5_0_0_beta69_rc8_1650464356 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69-rc8 [Build: 1650464356]",
	Sign:     "bBzPQVPQTxKvaRyAT05saGpau2J4yDZ+YD6fEaPSuwGllmGqXm6i9DM0WihlZsc1utRuTotgPyPE8wRXm9dkCQ==",
}

// Linux_5_0_0_beta69_rc8_1650474918 is Linux 5.0.0-beta69-rc8, build 1650474918.
var Linux_5_0_0_beta69_rc8_1650474918 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta69-rc8 [Build: 1650474918]",
	Sign:     "NokeLRYpWfaOqddwSter/EQ7Q6rzByReNAOIeapvIxmQZvtqKUlA4NNLerGaN91hyX/X+zVhOX6Eai0aTRX+DA==",
}

// MacOS_5_0_0_beta69_rc8_1650474918 is macOS 5.0.0-beta69-rc8, build 1650474918.
var MacOS_5_0_0_beta69_rc8_1650474918 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta69-rc8 [Build: 1650474918]",
	Sign:     "r4pznM4Mn9nHYbaNz0Ogmg0V868DmLr608lxehO16noWx+Xe/7yl7nAeAmVJ7NWr7si3B0nwSTofpCcW5cW5AQ==",
}

// Windows_5_0_0_beta69_1651157621 is Windows 5.0.0-beta69, build 1651157621.
var Windows_5_0_0_beta69_1651157621 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69 [Build: 1651157621]",
	Sign:     "Pwxtu+IgA90au8FGqOrRKWgACB/LZRaUrB5sLVHyG063GlJRlD4eHv9tJuojYqAppJJ7cMZW/br/FAXZNiNJDQ==",
}

// Linux_5_0_0_beta69_1651157621 is Linux 5.0.0-beta69, build 1651157621.
var Linux_5_0_0_beta69_1651157621 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta69 [Build: 1651157621]",
	Sign:     "Hte2iR5GHhNzFg/i7sZ6ERsYeJMy9wxO7AqDP9jb95XKTwEku3QJMkQHUH+2o7oV/wktCYrEmfIFZ0rEwxy0CQ==",
}

// Windows_5_0_0_beta69_1651486956 is Windows 5.0.0-beta69, build 1651486956.
var Windows_5_0_0_beta69_1651486956 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta69 [Build: 1651486956]",
	Sign:     "aPVvR6zqJNAuTtOa+t8OmUOljU9GwX2SovmNyzvbJV+tMbZP27mHoBSyl7ejRly9E+2QW68pBejlKYjZBMXRDQ==",
}

// Linux_5_0_0_beta69_1651486956 is Linux 5.0.0-beta69, build 1651486956.
var Linux_5_0_0_beta69_1651486956 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta69 [Build: 1651486956]",
	Sign:     "KlhsXgQKcjUalgrpqepGAjFdT95gjzPmV/SRDFn2qf/I/YcEw62GMNv/BxjkJ48gzIhgKxOtghWJKmzbuqMSCw==",
}

// MacOS_5_0_0_beta69_1651486956 is macOS 5.0.0-beta69, build 1651486956.
var MacOS_5_0_0_beta69_1651486956 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta69 [Build: 1651486956]",
	Sign:     "Z4zx1kgCpeoOUM2OYW507UacXR2qU5dHjtJz3W/KZdB4B401MloZc3jKsU8Bc+L0NHkqxZBT3/3xWaleOZiODQ==",
}

// Windows_5_0_0_qa_69_34_1651687542 is Windows 5.0.0-qa-69-34, build 1651687542.
var Windows_5_0_0_qa_69_34_1651687542 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-69-34 [Build: 1651687542]",
	Sign:     "wxe9CeISam7/fSMQKO/zwzxXyGAvZ4tCTrZSY7rrkqJRjIclDrqFMjIFy6BQfRF7LxxMWstp+LLglMYOd3Y0BA==",
}

// Linux_5_0_0_beta70_rc2_1651730595 is Linux 5.0.0-beta70-rc2, build 1651730595.
var Linux_5_0_0_beta70_rc2_1651730595 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta70-rc2 [Build: 1651730595]",
	Sign:     "ybhQnvk252kC2QPmGG8BqBfEU98t/nlyCIbN/HnAPbM4EpacsZLz3ouiwpBMa1/xfox8BMbFVW4XJQ83lQryAw==",
}

// Windows_5_0_0_t_2915_7_1652106526 is Windows 5.0.0-t-2915-7, build 1652106526.
var Windows_5_0_0_t_2915_7_1652106526 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-t-2915-7 [Build: 1652106526]",
	Sign:     "NuSMkmw5YsKd8CKKQkoXnc99UDgvZCWuSXNp/IE3+8tyrZ3t8wur4jqUfnBRx3x5gzuFDp9sGOfryJVrWTmDCg==",
}

// Windows_5_0_0_qa_70_1_1652113760 is Windows 5.0.0-qa-70-1, build 1652113760.
var Windows_5_0_0_qa_70_1_1652113760 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-70-1 [Build: 1652113760]",
	Sign:     "tgaxJYO8MasDp8oq/vRZ3pMDEYMejSzpOA3nt/8+BViY5XyrcwPOppheuKFv5Me+3IHtWL1ssu9CZoufB0auDQ==",
}

// Windows_5_0_0_beta70_rc3_1652281502 is Windows 5.0.0-beta70-rc3, build 1652281502.
var Windows_5_0_0_beta70_rc3_1652281502 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta70-rc3 [Build: 1652281502]",
	Sign:     "mI7gWzwqSXQ4RKQE/KxsnhYTBhCVVQ8r4c3ApE5naXa232IsFH5hPHAdQrekexULRQ4Qn3Dh0pxbXVheIb/7DQ==",
}

// Linux_5_0_0_beta70_rc3_1652281502 is Linux 5.0.0-beta70-rc3, build 1652281502.
var Linux_5_0_0_beta70_rc3_1652281502 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta70-rc3 [Build: 1652281502]",
	Sign:     "YRJLYVeUXVtz5bvcCALhEqRI4LZtk9+chwJLIhXhy5oojQiR1gqT8KaOVa5oN7ugJRBHPx73hh6hplwnLtEMDQ==",
}

// Windows_5_0_0_beta70_rc4_1652448464 is Windows 5.0.0-beta70-rc4, build 1652448464.
var Windows_5_0_0_beta70_rc4_1652448464 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta70-rc4 [Build: 1652448464]",
	Sign:     "JSogOYppjLZmIzz4FRt2eBciuZaYdS/LdoUsq2KvF4D3sFByBC8QdHpuEqJPmTKwCgleWPY2fCkPrCLVCliVAA==",
}

// Linux_5_0_0_beta70_rc4_1652448464 is Linux 5.0.0-beta70-rc4, build 1652448464.
var Linux_5_0_0_beta70_rc4_1652448464 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta70-rc4 [Build: 1652448464]",
	Sign:     "8G4ARIsaABohBur+uvAXxA1WtuaiKE7kCF7Os946xAiGou99vykuzDx9lEAh/FHtD2QLTHj2BMbpATiLGXy0AA==",
}

// Windows_5_0_0_qa_70_2_1652873884 is Windows 5.0.0-qa-70-2, build 1652873884.
var Windows_5_0_0_qa_70_2_1652873884 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-70-2 [Build: 1652873884]",
	Sign:     "nmWG+1gGxxoCku43Bzm5M0h7pcg9IlZNChTjq+mRVmdcQXAZ2+tKUSncP40qiGyKlJMWPUwDbB59AEdb6x3fDg==",
}

// Windows_5_0_0_beta70_rc5_1653042652 is Windows 5.0.0-beta70-rc5, build 1653042652.
var Windows_5_0_0_beta70_rc5_1653042652 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta70-rc5 [Build: 1653042652]",
	Sign:     "hrPP8RAT3TtakXdRpu+OpvlJqxMg3O/xjeAC7f0aYvumQCQm3CztZ8fbAmTyxZob2TSKzbVZvPIcDlpc9GN1AA==",
}

// Windows_5_0_0_beta70_rc6_1653467861 is Windows 5.0.0-beta70-rc6, build 1653467861.
var Windows_5_0_0_beta70_rc6_1653467861 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta70-rc6 [Build: 1653467861]",
	Sign:     "wk0OOY+kxOsgsTAbMUtcXU80quM3Zq2CyhTQqww0c9xzZx8jHr+8A93DRyDp/JVO+vhqpvvyaiIWAhsT9VJ6Cw==",
}

// Linux_5_0_0_beta70_rc6_1653467861 is Linux 5.0.0-beta70-rc6, build 1653467861.
var Linux_5_0_0_beta70_rc6_1653467861 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta70-rc6 [Build: 1653467861]",
	Sign:     "7qYi15DersnRo9GTgqVyhGhvHsGOkBuHYWlHIKJ5WBSHlwx2xve3GrKazde+ioJgSOv47RtxU5g6xQYfVqZOBw==",
}

// Windows_3_6_0_1654006450 is Windows 3.6.0, build 1654006450.
var Windows_3_6_0_1654006450 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1654006450]",
	Sign:     "t7q7tpbKMrsrP1iK+FWDRXAPozSTuKipEH9eRqzcAezF1aLTfh08YMhw8RHOZHaCCC3n7qxtEhzXP1cwS6UbAg==",
}

// Windows_5_0_0_beta70_rc7_1654093906 is Windows 5.0.0-beta70-rc7, build 1654093906.
var Windows_5_0_0_beta70_rc7_1654093906 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta70-rc7 [Build: 1654093906]",
	Sign:     "ZP9eAW6S8zldlCaIO5EF89Efb91dUMVQs1VLfcOZkfMoifuCz4zCqNR9kEfEzTTniik2CapTK3klbgZCnJ9RDQ==",
}

// Linux_5_0_0_beta70_rc7_1654093906 is Linux 5.0.0-beta70-rc7, build 1654093906.
var Linux_5_0_0_beta70_rc7_1654093906 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta70-rc7 [Build: 1654093906]",
	Sign:     "3AIq0BeGphKoauDyphnBY3HkIa7Si02lf+dsTSFh1lGBiUxUoPcbmkDDFQ0ODyNc99YHwNkUZMhtpXr/g+WBCA==",
}

// Windows_3_6_0_1654160172 is Windows 3.6.0, build 1654160172.
var Windows_3_6_0_1654160172 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1654160172]",
	Sign:     "hWniX9AkswRWML0/YinmyDFFoSLc78sn85HTjgZQh8764NhKIc4lKTfsSpyVov9VSb9SE/Yjf9WA0N2Q5x/oAQ==",
}

// MacOS_3_6_0_1654160172 is macOS 3.6.0, build 1654160172.
var MacOS_3_6_0_1654160172 = ClientVersion{
	Platform: "macOS",
	Version:  "3.6.0 [Build: 1654160172]",
	Sign:     "s/wew7fOQzeywZuGOlDfV81SZBV20Z5o/8MoHfYDyaA7d22NXxn1Nb5VMPbiJVxcJxNBuJaMP2BvZEed543cAg==",
}

// Windows_5_0_0_beta70_1654676785 is Windows 5.0.0-beta70, build 1654676785.
var Windows_5_0_0_beta70_1654676785 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta70 [Build: 1654676785]",
	Sign:     "/KFF7obhEgt2aJbZOCUiR824u81lUPlELT1CY32GJwwjap0RTu6LezXfejDdM8nJoUrDYQmXMu+dBVshNLulAQ==",
}

// Linux_5_0_0_beta70_1654676785 is Linux 5.0.0-beta70, build 1654676785.
var Linux_5_0_0_beta70_1654676785 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta70 [Build: 1654676785]",
	Sign:     "n43ssyQtR7el6jnlpNEazxzOyZ44M6RkCSehiTFUFh95ie/XXDFBEw7uDsyamktGqNFGdt1IGJ4sy5S++vMsBQ==",
}

// MacOS_5_0_0_beta70_1654676785 is macOS 5.0.0-beta70, build 1654676785.
var MacOS_5_0_0_beta70_1654676785 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta70 [Build: 1654676785]",
	Sign:     "K0h0JufWHcKF8a6b725AyV1YXJIOqbvW5JSHaQdxxcgxEsNhQaVCnJiQCcp7TGDTvgIgV876z3dLIk8xfG0OCA==",
}

// Windows_5_0_0_qa_2913_2_1655205340 is Windows 5.0.0-qa-2913-2, build 1655205340.
var Windows_5_0_0_qa_2913_2_1655205340 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-2913-2 [Build: 1655205340]",
	Sign:     "sVMWX0mvYy53XOm3APlfxWE+wSDxBie3UeiurJo0SWUrPEV5gOn03d0ZD0OqNPcwIzCKOC2pxQ+rTQ91OCWrAA==",
}

// Linux_5_0_0_qa_2913_2_1655205340 is Linux 5.0.0-qa-2913-2, build 1655205340.
var Linux_5_0_0_qa_2913_2_1655205340 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-qa-2913-2 [Build: 1655205340]",
	Sign:     "N6AztmwqY4uAU72SYYo+AQKMktUPLNwzetFmBsgMbNu0K1yBc+XdKtGpPk2nM6NW42GY+Zf5UTl3e9JTTNqkCw==",
}

// Windows_5_0_0_qa_2913_3_1655733884 is Windows 5.0.0-qa-2913-3, build 1655733884.
var Windows_5_0_0_qa_2913_3_1655733884 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-2913-3 [Build: 1655733884]",
	Sign:     "rLEgbE1A7AZAjdgoEkQSkEAcogHJnnz0TigqPPQ6mwAIHKpbJIIpaIKc0hyVn7ELl6B58W8XQ0/T00gt6lg3DQ==",
}

// Windows_5_0_0_beta71_rc1_1655990880 is Windows 5.0.0-beta71-rc1, build 1655990880.
var Windows_5_0_0_beta71_rc1_1655990880 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc1 [Build: 1655990880]",
	Sign:     "+fye+X6BDMa3nOA90wBTAqZQFy0O1wIGu1/cpGM5+iyFhLS0JYUk9xu3RlXviShDVMazH2JZ0BJ0eDcobT5tCg==",
}

// Windows_5_0_0_beta71_rc2_1656340141 is Windows 5.0.0-beta71-rc2, build 1656340141.
var Windows_5_0_0_beta71_rc2_1656340141 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc2 [Build: 1656340141]",
	Sign:     "C2Wq594czOp76S/4Pc4mtfEX8o862BJmMkmlSMe+Tco7xgykVcLyblHrE3kp4qeYC+71Hr2q3/Og5C9YdEBNBQ==",
}

// Linux_5_0_0_beta71_rc2_1656340141 is Linux 5.0.0-beta71-rc2, build 1656340141.
var Linux_5_0_0_beta71_rc2_1656340141 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc2 [Build: 1656340141]",
	Sign:     "gKBdAhcdB/S/cXy/oGXWdTvxjubFr+hadQ3ONE6XVp6dMzWNMLP4MgTOBIxGu5TbEMlSeUHHdZWHrpr2CUD0Bg==",
}

// Windows_5_0_0_qa_71_1_1656589081 is Windows 5.0.0-qa-71-1, build 1656589081.
var Windows_5_0_0_qa_71_1_1656589081 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-1 [Build: 1656589081]",
	Sign:     "mKtr9xGv8lQRCJFt8+TKF3sWtlN6uvkGYXepfiGfk5I9TZQsQqrmJ3Ji1xB/BSBVqJoRAQR7fN8uflwKPiLKDA==",
}

// Windows_5_0_0_qa_71_2_1657105351 is Windows 5.0.0-qa-71-2, build 1657105351.
var Windows_5_0_0_qa_71_2_1657105351 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-2 [Build: 1657105351]",
	Sign:     "DxobPbJpTnYap0LcyOL3+XvYi0ji1715HukXtOn/OUSL4lIyYUh8bhNNrs1adxe12+B8gnb//YjHBNNMmOxeAg==",
}

// Windows_5_0_0_beta71_rc3_1657116184 is Windows 5.0.0-beta71-rc3, build 1657116184.
var Windows_5_0_0_beta71_rc3_1657116184 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc3 [Build: 1657116184]",
	Sign:     "D2rmZyzrtXmDDFoMsmSMtLwZp5GjHKsr5E0DAmery/c6THt3qUgq+Ft25Yd3J5BchiHFXW0b/IjYqxPZn4vzDQ==",
}

// Windows_5_0_0_beta71_rc4_1657196441 is Windows 5.0.0-beta71-rc4, build 1657196441.
var Windows_5_0_0_beta71_rc4_1657196441 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc4 [Build: 1657196441]",
	Sign:     "N1UhStcYNBaiPlFb1DvBha6wCFx9SdCWnXdh2ZMRc9WYzKFHXVu59GUn4IxAAH1M67dVwIYRJQpefDsas3rOCw==",
}

// Linux_5_0_0_beta71_rc4_1657196441 is Linux 5.0.0-beta71-rc4, build 1657196441.
var Linux_5_0_0_beta71_rc4_1657196441 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc4 [Build: 1657196441]",
	Sign:     "dJz/qSD5sUDoZRZhsAN9XeqVPIcnq8i6rM0wwfFFrMc48fN13j+sMptaFh2TonzDo/S9/2UAytN6UUDrF5nxAw==",
}

// Windows_5_0_0_qa_71_3_1657550670 is Windows 5.0.0-qa-71-3, build 1657550670.
var Windows_5_0_0_qa_71_3_1657550670 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-3 [Build: 1657550670]",
	Sign:     "LlG39Ix9oFdfIjrjw40un1b/k4rYag0XT0yi7Lp5AQxQ/WqJCiPut9oO8HZZ1Xxoq/XJJywfnjwxKQOpN2bIDw==",
}

// Windows_5_0_0_beta71_rc6_1657710601 is Windows 5.0.0-beta71-rc6, build 1657710601.
var Windows_5_0_0_beta71_rc6_1657710601 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc6 [Build: 1657710601]",
	Sign:     "Fo4k9MsMV7HQkoUxNDk9jCd7cKEmFXCj0bS83yij0Q7IyBRvcg2PU1bpL6YPxduJ5ssCOjS6AdB4h9XS3cdBCw==",
}

// Linux_5_0_0_beta71_rc6_1657710601 is Linux 5.0.0-beta71-rc6, build 1657710601.
var Linux_5_0_0_beta71_rc6_1657710601 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc6 [Build: 1657710601]",
	Sign:     "h7en9dun2t8UOPN3jRRJlf4qLI6Lj2xr4UhqZdIs+H9QqD4Ox9C4Iwl0kjgldi4GV1AbuwXi5Fkfe72AwHP3CQ==",
}

// Windows_5_0_0_tra_09_1657880771 is Windows 5.0.0-tra-09, build 1657880771.
var Windows_5_0_0_tra_09_1657880771 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-tra-09 [Build: 1657880771]",
	Sign:     "7tCcJLRtLuVGl8SVAdwpsqX5c9k+cNuQsuAjXTcvk/DVfITmZZet7mSh99qb75T8yZnbcfZOiyd8KW23BEXtBg==",
}

// Linux_5_0_0_beta71_rc7_1658908364 is Linux 5.0.0-beta71-rc7, build 1658908364.
var Linux_5_0_0_beta71_rc7_1658908364 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc7 [Build: 1658908364]",
	Sign:     "1DxbHsONSNvnCT5VHmwjx1r7+E6WkbNdoJHQK+9Yo9hLviUbJ1SyGk1okkYc45y5rYUOls5/9A0yLhmn87X4Dw==",
}

// MacOS_5_0_0_beta71_rc7_1658908364 is macOS 5.0.0-beta71-rc7, build 1658908364.
var MacOS_5_0_0_beta71_rc7_1658908364 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta71-rc7 [Build: 1658908364]",
	Sign:     "lqXrUQqxwOTLO+hAH0DoMiOKJtDGE/oO4p7dkWudsZx+VNpepuRMLzTff6RA2XAqGqd+McHK90ohBDW77ZUYCw==",
}

// Windows_5_0_0_qa_71_4_1659089293 is Windows 5.0.0-qa-71-4, build 1659089293.
var Windows_5_0_0_qa_71_4_1659089293 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-4 [Build: 1659089293]",
	Sign:     "kmmMWX1liFabpUSxVFnt9FcWylRrqJmEQmkaQ/Fv6EB4vak5Y9ld2gkoqpp4ahWSf4+OLQ0YE0/sLO71yIekAQ==",
}

// Windows_5_0_0_qa_71_5_1659598962 is Windows 5.0.0-qa-71-5, build 1659598962.
var Windows_5_0_0_qa_71_5_1659598962 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-5 [Build: 1659598962]",
	Sign:     "6/S2eqmQq+4D6OcUY/FqbPo++n1aM4NU6NUJhe26v3IIYXU0igeF22Qw8TgxwXufeRQjR+F/LoX5Q8X+6VaVDQ==",
}

// Windows_5_0_0_qa_71_6_1659957641 is Windows 5.0.0-qa-71-6, build 1659957641.
var Windows_5_0_0_qa_71_6_1659957641 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-6 [Build: 1659957641]",
	Sign:     "hdcRpNOH7DTDDVINjARSm8dpsp5UlK/YmaTzHPZIEXZcrf6qiJeEvW/5vrlGg54GXjUmASNFV3MAVXLWFYupDQ==",
}

// Windows_5_0_0_qa_71_7_1661262442 is Windows 5.0.0-qa-71-7, build 1661262442.
var Windows_5_0_0_qa_71_7_1661262442 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-7 [Build: 1661262442]",
	Sign:     "L9risxlPhXSqSx8wFpUZz+e+YHA+AEN0n5EPebpjF18hYiGJGUlirLBbbF5QP/URzZD37/3I5KnR0uNw1JhCAQ==",
}

// Windows_5_0_0_beta71_rc9_1661354034 is Windows 5.0.0-beta71-rc9, build 1661354034.
var Windows_5_0_0_beta71_rc9_1661354034 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc9 [Build: 1661354034]",
	Sign:     "1PPbMKaszRT2LZOOZJeyiomDd+P6j45NhycdYdBo1AW+1xOQYC4ZG4nTUSprOsAuIjxjSWf4Cb3iVFolMlK4Bg==",
}

// Windows_5_0_0_qa_3231_7_1661783707 is Windows 5.0.0-qa-3231-7, build 1661783707.
var Windows_5_0_0_qa_3231_7_1661783707 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-3231-7 [Build: 1661783707]",
	Sign:     "c/OT4xGrILSDLZkndPPdOp65ME/YRJREHRlqySctGfM4f/1T12dNZ0ESjCAAMwN3F3+8/GhpgAulW39R2tO2Dw==",
}

// Windows_5_0_0_beta71_rc12_1661967524 is Windows 5.0.0-beta71-rc12, build 1661967524.
var Windows_5_0_0_beta71_rc12_1661967524 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc12 [Build: 1661967524]",
	Sign:     "BoSYWcyXQT0Ry2hfU1wXpGyEie9ZGFNbDy8jPk9Mv0wgs+IPQNx5HtHeFjE4dtAKth04fgJdejDXVI7GZU8dAA==",
}

// Windows_5_0_0_beta71_rc13_1662123474 is Windows 5.0.0-beta71-rc13, build 1662123474.
var Windows_5_0_0_beta71_rc13_1662123474 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc13 [Build: 1662123474]",
	Sign:     "zynXO8tH7q0COrhZJZD//yA223JzNu6nPnN/rt9YwI9Jq2QUNSaDzE6gHJMTv4X7vHsab+Z3g0VqUPIPTyINBQ==",
}

// Linux_5_0_0_beta71_rc13_1662123474 is Linux 5.0.0-beta71-rc13, build 1662123474.
var Linux_5_0_0_beta71_rc13_1662123474 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc13 [Build: 1662123474]",
	Sign:     "rEk3lv0SxO824CyQYSAzIKaR6GxWk251J2NytRRL4pUFagb5UcKsznyhPV0qO2Vn8JdfdU5zMfTX2e3MxDkFBw==",
}

// MacOS_5_0_0_beta71_rc13_1662123474 is macOS 5.0.0-beta71-rc13, build 1662123474.
var MacOS_5_0_0_beta71_rc13_1662123474 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta71-rc13 [Build: 1662123474]",
	Sign:     "VkCcAk5+kRgY31T3BlX5fRo68isELG+RyQEO8ZZSh1SBhbmY9RTVxHSQZ4mODJKTsn3qNCSaCWKpVXBdd1+JAw==",
}

// Windows_3_6_0_1662544077 is Windows 3.6.0, build 1662544077.
var Windows_3_6_0_1662544077 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1662544077]",
	Sign:     "qSw1K3cyE/P3KDtGLB8OHU387sdFN3Ps2ztPfkPAZx/44/uaYl4Zh5qxuQWmOza/KbyefWBkJPxMjN9z2zjCCQ==",
}

// Linux_3_6_0_1662544077 is Linux 3.6.0, build 1662544077.
var Linux_3_6_0_1662544077 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1662544077]",
	Sign:     "9j6NSQpYSE0imFRgcJJKxUBc35bofwSZze00ftKzNspjh63/B899VbJ+zASN4IUm6GK13vNLiOkRyz8SyoEECw==",
}

// Windows_5_0_0_qa_3305_rc13_1662565498 is Windows 5.0.0-qa-3305-rc13, build 1662565498.
var Windows_5_0_0_qa_3305_rc13_1662565498 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-3305-rc13 [Build: 1662565498]",
	Sign:     "HCuDHsiQvNAn9tNHi8Ws3m06EQcChO3zh0+nzWWhpOaog/QD4PECVR/KKivIh3FTXpsgUzMgRwoZYlQNKcpoCQ==",
}

// Windows_5_0_0_qa_71_8_1662994626 is Windows 5.0.0-qa-71-8, build 1662994626.
var Windows_5_0_0_qa_71_8_1662994626 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-8 [Build: 1662994626]",
	Sign:     "sYcKDUwhl8ZfrgyU7Xw0yJKV86RXvjnIfLrTQammSnqYCf72Hg1GnVBdWEOURngerrqF7WBW0frUpkYi6d5OCw==",
}

// Windows_5_0_0_beta71_rc14_1663228073 is Windows 5.0.0-beta71-rc14, build 1663228073.
var Windows_5_0_0_beta71_rc14_1663228073 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc14 [Build: 1663228073]",
	Sign:     "vWB3J+ostQ8z6ydFxCOe2vp32jgGYpq38asWbXe7gLvPQaNx9gQrc/dPezrauZoUv+7SyAWnuqyQncAb7nnQBw==",
}

// Linux_5_0_0_beta71_rc14_1663228073 is Linux 5.0.0-beta71-rc14, build 1663228073.
var Linux_5_0_0_beta71_rc14_1663228073 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc14 [Build: 1663228073]",
	Sign:     "4HTdstOwcwrKLIokg4SVrMkRtNLj35qfVfSryRYXU6YKg/fIQkvDw7LWVBfxSfdh42k609KuIA8ElXCtc91cCA==",
}

// Windows_5_0_0_qa_pre_crypto_fixes_1663230086 is Windows 5.0.0-qa-pre-crypto-fixes, build 1663230086.
var Windows_5_0_0_qa_pre_crypto_fixes_1663230086 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-pre-crypto-fixes [Build: 1663230086]",
	Sign:     "CIkiiGfRaghePf9DU3YkDA5gdS4YqcIz/74nNwZ6ic8q+1FxN4R3XYwDnAL39F6S1FAbVM1ulbGgazaMAIGcCg==",
}

// Windows_5_0_0_qa_crypto_fixes_1_1663662700 is Windows 5.0.0-qa-crypto-fixes-1, build 1663662700.
var Windows_5_0_0_qa_crypto_fixes_1_1663662700 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-crypto-fixes-1 [Build: 1663662700]",
	Sign:     "HlXCMwcwTIdsnM7xHi9mnVvaru+8QII8ZmhWhGZSuV/hVeDL9BO+/wgdtqp7d9Ql4EyN0AYLOhMBbC0kWQLsDA==",
}

// Windows_5_0_0_qa_crypto_test_on_rc14_2_1663768885 is Windows 5.0.0-qa-crypto-test-on-rc14-2, build 1663768885.
var Windows_5_0_0_qa_crypto_test_on_rc14_2_1663768885 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-crypto-test-on-rc14-2 [Build: 1663768885]",
	Sign:     "WxA1UVobQ6diOypmuEYoBZk6wOvfSiPM0/0wZ1dno4LWz8Y9qFu1Y1s4VhleGCVpTHmwNZvaPAxa/GHOSFmPBQ==",
}

// Windows_5_0_0_ui_polishing_11_1664554487 is Windows 5.0.0-ui-polishing-11, build 1664554487.
var Windows_5_0_0_ui_polishing_11_1664554487 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-ui-polishing-11 [Build: 1664554487]",
	Sign:     "ClAwrssS0bu5TJrLDm2s+g4TgA77Dmr85W+nhoJq6sLg6aZ2KRB6n33KD3NTKw2lUL1T8xOdEmILdv9I8+S9AQ==",
}

// Windows_5_0_0_qa_crypto_fixes_3_1666096977 is Windows 5.0.0-qa-crypto-fixes-3, build 1666096977.
var Windows_5_0_0_qa_crypto_fixes_3_1666096977 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-crypto-fixes-3 [Build: 1666096977]",
	Sign:     "h7dOdFSWU2EZA22ZRtDOl/FxKmMPOAeYlzmcqJG9EwvWZHwpWyFshxWWygCtNAOTECxa5+qbwbgCUSFalBvUBg==",
}

// Windows_5_0_0_qa_71_9_1666179837 is Windows 5.0.0-qa-71-9, build 1666179837.
var Windows_5_0_0_qa_71_9_1666179837 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-9 [Build: 1666179837]",
	Sign:     "XF9j3k9qcKCXkcBpKek8toKZMBNG3gCj983pca9mT2AS8c615qvRkRIImnSnQQAq4s1EYzLljcnFEMkzcxnVBw==",
}

// Windows_5_0_0_qa_71_10_1666256439 is Windows 5.0.0-qa-71-10, build 1666256439.
var Windows_5_0_0_qa_71_10_1666256439 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-10 [Build: 1666256439]",
	Sign:     "MvDLE/Sr1L8Pa+y+eHEye5hsE9dIdeWDpZnjXwv7lNE1L10NRAhJHTizhErqU4XyOoSqF/O/6Akss1FSpVTGDA==",
}

// Windows_5_0_0_qa_71_12_1666360320 is Windows 5.0.0-qa-71-12, build 1666360320.
var Windows_5_0_0_qa_71_12_1666360320 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-12 [Build: 1666360320]",
	Sign:     "KgnXG1mnZ507h8mkOPmIXHsSIowFJMhPm/hdykmd8tSUfp19csom/yWXT4QsnsKUjfjtLXBCjr1murCQgskUAA==",
}

// Windows_5_0_0_beta71_rc15_1666706353 is Windows 5.0.0-beta71-rc15, build 1666706353.
var Windows_5_0_0_beta71_rc15_1666706353 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc15 [Build: 1666706353]",
	Sign:     "UhMZLawOeXuCky3TJPgLHXIPk3iTIR097hwl6755oQhslTUeTtLjZ/GJPowq7RjnJt0zAvOjWSJwxSBhZMNTCA==",
}

// Linux_5_0_0_beta71_rc15_1666706353 is Linux 5.0.0-beta71-rc15, build 1666706353.
var Linux_5_0_0_beta71_rc15_1666706353 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc15 [Build: 1666706353]",
	Sign:     "NAGcBwzMD/GF1Gkyxi5LvDcQIe9wY2ZKMMXVjGEy1meRAY6nyzgcavGVOnO9dxOVgd1bqfllj6HzuWXMTKMCAg==",
}

// Windows_3_6_0_1666781655 is Windows 3.6.0, build 1666781655.
var Windows_3_6_0_1666781655 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1666781655]",
	Sign:     "cKMK6yn54MkK6J46AUfQyuHVij9TYGyOGgWeJYNPBMUmvv5Qr9GUxoeSnNBHTCqV89Et7v01H7Kzie4+tNgsDQ==",
}

// Linux_3_6_0_1666781655 is Linux 3.6.0, build 1666781655.
var Linux_3_6_0_1666781655 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1666781655]",
	Sign:     "PdBDIrgplpy9//chwhIRbrLyiQarUll/uEh0xdCcvrLHjY2LG+B/N/RpDJfSZkrXoojRHyjcTPBV47/HXc65Cg==",
}

// MacOS_3_6_0_1666781655 is macOS 3.6.0, build 1666781655.
var MacOS_3_6_0_1666781655 = ClientVersion{
	Platform: "macOS",
	Version:  "3.6.0 [Build: 1666781655]",
	Sign:     "0GQU2HS1HYA14STZx829IzPug8yXuWL9O89x+WSWvJTBhNovmSk+G8v4nzXpfz+B85tBrCdhBSFIZW2Meo6FDg==",
}

// Windows_5_0_0_qa_3230_1_1667372765 is Windows 5.0.0-qa-3230-1, build 1667372765.
var Windows_5_0_0_qa_3230_1_1667372765 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-3230-1 [Build: 1667372765]",
	Sign:     "lXuPP3Y0x5qjfNL7Yp8BeGImy7oS95yEmalinun3Yxub7JX4E8ru1xU8HAW8/xVKhYzlOeVrYEwvV4bZwh/HBA==",
}

// Windows_5_0_0_qa_71_15_1667384582 is Windows 5.0.0-qa-71-15, build 1667384582.
var Windows_5_0_0_qa_71_15_1667384582 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-15 [Build: 1667384582]",
	Sign:     "wlf/D1ISErk9dDTYuhFdOPI5Tv9snRg01RFoFmvd0v1m49HF89HR8DpsM02zOT6M1g3iC5afB7Y1QgEpL1U8DQ==",
}

// Windows_5_0_0_qa_3230_2_1667811609 is Windows 5.0.0-qa-3230-2, build 1667811609.
var Windows_5_0_0_qa_3230_2_1667811609 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-3230-2 [Build: 1667811609]",
	Sign:     "QdlYsyxyqIyE6wIXGOCKxjt6IeMXGgtAGBzU8CRZwf/+R8Xbda5jIfrcV87uxinWpFD3Fgx78zgDdRSDOfMPAg==",
}

// Android_3_6_0_1667819930 is Android 3.6.0, build 1667819930.
var Android_3_6_0_1667819930 = ClientVersion{
	Platform: "Android",
	Version:  "3.6.0 [Build: 1667819930]",
	Sign:     "DMxIGKedSqo66DGSTd/vCa4bP0QQPP5TYXQcjML9KARTXD9cUmsSzWVSuZN5L4wQQRDcKJ2w9QWxHZP1KQrRCw==",
}

// Windows_5_0_0_qa_71_17_1667845499 is Windows 5.0.0-qa-71-17, build 1667845499.
var Windows_5_0_0_qa_71_17_1667845499 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-17 [Build: 1667845499]",
	Sign:     "Tp1dTr/0K+XDkRIHTsnROsZc1n3viE0eWS14E39VVcBs51o+1jZtpspWWvTbcCEWmRHx53CPzCRIw+uE1jmjAQ==",
}

// Windows_5_0_0_qa_71_18_1668000845 is Windows 5.0.0-qa-71-18, build 1668000845.
var Windows_5_0_0_qa_71_18_1668000845 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-18 [Build: 1668000845]",
	Sign:     "WUvAlTTuoTXCFa/st2hB0dc3hKjuIP5EMrTGrtMRUXdSIX2P3aER5AcTyOf3p2BLmoUyNPXUT619x/PlFoB7Cg==",
}

// Windows_3_6_0_1668022263 is Windows 3.6.0, build 1668022263.
var Windows_3_6_0_1668022263 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1668022263]",
	Sign:     "jNUeF6ydYPJp6CpoA2Nm8FcmxPTwj8bFJmmzo/Ch2B9L2CU2rrgLJedcQM3NjAncESYYywUiFR0+BsljvaTNAQ==",
}

// Windows_5_0_0_qa_71_19_1668103173 is Windows 5.0.0-qa-71-19, build 1668103173.
var Windows_5_0_0_qa_71_19_1668103173 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-19 [Build: 1668103173]",
	Sign:     "ehpTF8nUjAKywymSuCubQs21DDqyuJugOXuv9dtWSxATiGZ53EzuUkj2Wj4hiiWScEv2VZ5btjr4YSui3DI+Cg==",
}

// Windows_5_0_0_qa_71_21_1668448738 is Windows 5.0.0-qa-71-21, build 1668448738.
var Windows_5_0_0_qa_71_21_1668448738 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-21 [Build: 1668448738]",
	Sign:     "VlC4gvRTuUkY9H9QktlbLg8qPVmX2ibrrV5Xtle83CQNUZnAj119TCgTPDhE147ZdN1fLO7GrPRNgSfeE5+2Aw==",
}

// Windows_5_0_0_qa_71_24_1668688049 is Windows 5.0.0-qa-71-24, build 1668688049.
var Windows_5_0_0_qa_71_24_1668688049 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-24 [Build: 1668688049]",
	Sign:     "AqJemaMYTMwn76j+AG5DkGXfmb79ytLdH5tmRpMTkMQ41s4vjr2j81LrYojevsTc8elodUT+pW3LicVJ5/yHAg==",
}

// Windows_5_0_0_beta71_rc16_1668705307 is Windows 5.0.0-beta71-rc16, build 1668705307.
var Windows_5_0_0_beta71_rc16_1668705307 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71-rc16 [Build: 1668705307]",
	Sign:     "j661q6B0F7v1EWt3fnr5rkBaSgP3v1LZtKOfhSsbnNz0E5+MuoDPS71GP89uWdf5g/rvwh8gXTNRqgt64+EzBA==",
}

// Linux_5_0_0_beta71_rc16_1668705307 is Linux 5.0.0-beta71-rc16, build 1668705307.
var Linux_5_0_0_beta71_rc16_1668705307 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71-rc16 [Build: 1668705307]",
	Sign:     "S8QjXs9J1riVIW/eMtHE5tjV+iHgWZzB2ts7G/K21KEdlsjEk2TR8FTd+C2ouj64loIwhzl/Rilu26ewqC1/DQ==",
}

// Windows_5_0_0_qa_71_26_1669036474 is Windows 5.0.0-qa-71-26, build 1669036474.
var Windows_5_0_0_qa_71_26_1669036474 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-26 [Build: 1669036474]",
	Sign:     "akylWlFzsOJVvpbNZG0AaDKN7zYfykkto7ZI08ws8MmecZgDidpndxPcfp8/3My0AglFPuRKakSrONWXjo8/Dw==",
}

// Windows_5_0_0_qa_71_29_1669300286 is Windows 5.0.0-qa-71-29, build 1669300286.
var Windows_5_0_0_qa_71_29_1669300286 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-71-29 [Build: 1669300286]",
	Sign:     "0PJ3NnIAyxuRQJuO7iHGOysZDEQn9Vf1S5LHyfRQLbbAiiwcnU5RQNtyu5eaWsFOfnqGwI97GbWLAysQqqbjDw==",
}

// Windows_5_0_0_beta71_1670237565 is Windows 5.0.0-beta71, build 1670237565.
var Windows_5_0_0_beta71_1670237565 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta71 [Build: 1670237565]",
	Sign:     "AGYCEceJGMGnWX3PkCUS4Kaso8LyYZNt9iALUTVg/11505ulqPBlQPygsG6X399SF2FD6jCR4bCOxSTzLlKDDA==",
}

// Linux_5_0_0_beta71_1670237565 is Linux 5.0.0-beta71, build 1670237565.
var Linux_5_0_0_beta71_1670237565 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta71 [Build: 1670237565]",
	Sign:     "5+PHxwb9AgALL90T6PtIl6H/En+B/x7RuAtwtsVfCLDgKUEcBNAjW4LTzZR/I64STXv5QbHFrUBBh28VgtO9BQ==",
}

// MacOS_5_0_0_beta71_1670237565 is macOS 5.0.0-beta71, build 1670237565.
var MacOS_5_0_0_beta71_1670237565 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta71 [Build: 1670237565]",
	Sign:     "FK2fuBMl6iutX7Zb490ged1StULGIUbNA+i9HH6hqVm2RdmuLQ27q0SzI2i3n2lVh9pP7SZBgItxWcYNAp9IAg==",
}

// Windows_5_0_0_beta72_1671465207 is Windows 5.0.0-beta72, build 1671465207.
var Windows_5_0_0_beta72_1671465207 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta72 [Build: 1671465207]",
	Sign:     "P7cFw4WFvfGRtGtfGUwM5KpF1FK1M3B1aK91ZX3wwWBht8J1fp0Spd11HhtgzXNrHD88yXbBdLqxpxgBxyEHCA==",
}

// Windows_5_0_0_beta72_rc1_1671465207 is Windows 5.0.0-beta72-rc1, build 1671465207.
var Windows_5_0_0_beta72_rc1_1671465207 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta72-rc1 [Build: 1671465207]",
	Sign:     "wCy5wBohgq/a1VU630R4Vm7XjMincMH4gwFMxZlejhexDhq1jx+D/7fw2LOroNib7R9nURSHbKj9prZG8AtKDQ==",
}

// Linux_5_0_0_beta72_1671465207 is Linux 5.0.0-beta72, build 1671465207.
var Linux_5_0_0_beta72_1671465207 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta72 [Build: 1671465207]",
	Sign:     "uI8R806y9u77z78GILvKmJB+f3ZXP+by073xKtIJCmNJKXFTTlHqRADAuGEUWbqI9+NaDtSlFHywb5VVxEYcAA==",
}

// Windows_5_0_0_qa_73_3_1673952226 is Windows 5.0.0-qa-73-3, build 1673952226.
var Windows_5_0_0_qa_73_3_1673952226 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-73-3 [Build: 1673952226]",
	Sign:     "X1dCHqr0/4KQJe5vRa4F+TG6yFqJls4Pp+x5mAuvKSHMKQ+6bIa4jNVNhlBSMGoxaOQwhObFzHqMb49C4YKLBg==",
}

// Windows_5_0_0_qa_73_11_1676933790 is Windows 5.0.0-qa-73-11, build 1676933790.
var Windows_5_0_0_qa_73_11_1676933790 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-73-11 [Build: 1676933790]",
	Sign:     "xSD6HeHTdSi2lt1aMKz+QiaFjaLk8++hczMJvatTLlqIn8Gm6y8kmu43rwdTyanU0H5EQW53mMUcIlV+bPCbAg==",
}

// Windows_5_0_0_beta73_rc1_1677076356 is Windows 5.0.0-beta73-rc1, build 1677076356.
var Windows_5_0_0_beta73_rc1_1677076356 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta73-rc1 [Build: 1677076356]",
	Sign:     "WndD7PSfy+gl/haCDKGrD3lbam0i4l4AFpbFVc5GwVeteR7nzpjE99SvDn0CMMAYk3vYBKjMP+nsAWiylbYJAA==",
}

// Linux_5_0_0_beta73_rc1_1677076356 is Linux 5.0.0-beta73-rc1, build 1677076356.
var Linux_5_0_0_beta73_rc1_1677076356 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta73-rc1 [Build: 1677076356]",
	Sign:     "tTaatH5xdPJ/ObMlbbSDBiov2+kdtlEVw8MF3K4xFLrug6lerU6Xdqalcsa9sAQqhOogDaifRAVpD6oEes7rCg==",
}

// Windows_5_0_0_beta73_rc3_1677756122 is Windows 5.0.0-beta73-rc3, build 1677756122.
var Windows_5_0_0_beta73_rc3_1677756122 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta73-rc3 [Build: 1677756122]",
	Sign:     "A+TukrQZwCKghG/xlGk5Bo8wi0WAKNK/SPfOMZNeCC3G0ZDN1h3/lcbiGtuSpBu5tYd5n+/Q0Pjh3WjvYOEVDA==",
}

// Linux_5_0_0_beta73_rc3_1677756122 is Linux 5.0.0-beta73-rc3, build 1677756122.
var Linux_5_0_0_beta73_rc3_1677756122 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta73-rc3 [Build: 1677756122]",
	Sign:     "3ugSo0Eq1aEVI4LG3+E3CmtvLBxv6qH5hYZLZu17uJC05okFcmdDRRBG3Tj5jKEy2v6y1YOsLMwArDp1xZfTDg==",
}

// Windows_5_0_0_beta73_1679397420 is Windows 5.0.0-beta73, build 1679397420.
var Windows_5_0_0_beta73_1679397420 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta73 [Build: 1679397420]",
	Sign:     "EWhqEP8V36cleD0Cl7AQnG6M82KMDwQbiEObDmcDC5AAF7l13BbWje0j4yNivIOnAwkvneUmRe8RK0LLP9CHBA==",
}

// Linux_5_0_0_beta73_1679397420 is Linux 5.0.0-beta73, build 1679397420.
var Linux_5_0_0_beta73_1679397420 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta73 [Build: 1679397420]",
	Sign:     "7b8MXzq0z59NIrR88V3l/oCfUaMfpNAtosNBj20zWC1fh0vVvf/O+tyG6XiiJfQyEHc+OJ1gbx/z7roErekWBA==",
}

// OSX_5_0_0_beta73_1679397420 is OS X 5.0.0-beta73, build 1679397420.
var OSX_5_0_0_beta73_1679397420 = ClientVersion{
	Platform: "OS X",
	Version:  "5.0.0-beta73 [Build: 1679397420]",
	Sign:     "weeF0ZNGrlUvB8vIQCvfLqcNV53aWJqPaqwo+hACJoomwdqZ7n1+VW1RxSedMy/ii/GtgyTbUiCojhH2MCAoAA==",
}

// Windows_5_0_0_qa_74_1_1679398750 is Windows 5.0.0-qa-74-1, build 1679398750.
var Windows_5_0_0_qa_74_1_1679398750 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-1 [Build: 1679398750]",
	Sign:     "A87gwqv6WCQAVkKmLJo11jss00zFyC4Yh3gTRnAng5vOxGHB8zclsJTizu12iT0Mwpa4sYTHPIS2f+zqEcCpCQ==",
}

// Windows_5_0_0_qa_74_2_1679472836 is Windows 5.0.0-qa-74-2, build 1679472836.
var Windows_5_0_0_qa_74_2_1679472836 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-2 [Build: 1679472836]",
	Sign:     "AXcwrSeKswE5Yd/sQRd2bqH6NqnEba5l2nWoMHL/3LvZRCAf4QElRuHtLvNAZbntlEQ8/GOe+g+8ejCn83rAAQ==",
}

// Windows_5_0_0_qa_74_3_1679578894 is Windows 5.0.0-qa-74-3, build 1679578894.
var Windows_5_0_0_qa_74_3_1679578894 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-3 [Build: 1679578894]",
	Sign:     "25zH3oeWqo0eYSWiUWxFHNlK3NK5qZPUVH8yEEaXHquGF6xoZPB9QWbjfkEaLB607j3Us1mviH7/Q47/3GpvDg==",
}

// Windows_5_0_0_qa_74_5_1680085518 is Windows 5.0.0-qa-74-5, build 1680085518.
var Windows_5_0_0_qa_74_5_1680085518 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-5 [Build: 1680085518]",
	Sign:     "/X5xXLBPrLClWkivAnMJCz+QIBmFk9fFie8sNg69OdN/xwBQrX6naf2IehfxLdd+BBWX/5TsDjuPJqJwhK1FBg==",
}

// Windows_5_0_0_qa_74_7_1681481733 is Windows 5.0.0-qa-74-7, build 1681481733.
var Windows_5_0_0_qa_74_7_1681481733 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-7 [Build: 1681481733]",
	Sign:     "4qdm8R3gNHlXDV9PS2CtV3Fe9SN7Mjgt82X+iZmqwMXk9B0g9vCyK62G7h2nr/qcqSopPXR4652xMsSQPYVvDQ==",
}

// OSX_3_6_0_1681728436 is OS X 3.6.0, build 1681728436.
var OSX_3_6_0_1681728436 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.0 [Build: 1681728436]",
	Sign:     "MZzEbAN51fl7FGiF51T32nHz5tySXH3te4EEZip5rImRNX1Ey3bBQkahN1PYhURNAQxAtIupczX5iGMmvKm4DA==",
}

// Windows_5_0_0_qa_74_8_1681821920 is Windows 5.0.0-qa-74-8, build 1681821920.
var Windows_5_0_0_qa_74_8_1681821920 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-8 [Build: 1681821920]",
	Sign:     "wBuvBhPgbvXmtEOavMpF/6X7xvHkd0PcrNmob7nSr5trxi5HFGjzvOZU19p56yzOStI077LvVJcQtjVha2uXCA==",
}

// Windows_5_0_0_qa_74_10_1682065994 is Windows 5.0.0-qa-74-10, build 1682065994.
var Windows_5_0_0_qa_74_10_1682065994 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-10 [Build: 1682065994]",
	Sign:     "fCODC/wSy5xu9VXPjK3MsRur4MqN/mSLcP/DdbQ2u/KNgQmpuQEsVelmbrf5AvJUQ9YhmXyx8aMvTnG9kHSnCQ==",
}

// Windows_5_0_0_qa_dc_1_1682080978 is Windows 5.0.0-qa-dc-1, build 1682080978.
var Windows_5_0_0_qa_dc_1_1682080978 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-dc-1 [Build: 1682080978]",
	Sign:     "0p63hM9RbR65x093OWBlS9g0We6lNfYA+IWN99TZ23HXzWXuvfukMK6lIviHJkNSFWCBxhGQFmFi9lttH00vCA==",
}

// Windows_5_0_0_qa_74_11_1682337867 is Windows 5.0.0-qa-74-11, build 1682337867.
var Windows_5_0_0_qa_74_11_1682337867 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-11 [Build: 1682337867]",
	Sign:     "BhUfmE4EX5h9gjKKtfO1JQ61sIdzZfm1IcvA4FNU8BtmA2DSzUJ9uDWFrq60h7lh33wkktDCzlXL7j8PNQChCg==",
}

// Windows_5_0_0_qa_74_13_1682589154 is Windows 5.0.0-qa-74-13, build 1682589154.
var Windows_5_0_0_qa_74_13_1682589154 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-13 [Build: 1682589154]",
	Sign:     "4OMk6jcMvJc/P3zaojn8+laRQzG/vnmEkWEmTpQzIsTcPzKOu5irT82YpOtlp+BIxFDGb8onygu/turJjHLiDA==",
}

// Windows_5_0_0_qa_74_14_1682680770 is Windows 5.0.0-qa-74-14, build 1682680770.
var Windows_5_0_0_qa_74_14_1682680770 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-14 [Build: 1682680770]",
	Sign:     "bwZm9gRSoUSRTWCcc1N0ZuKs+xznjBKErt3myq9YlXzdC/jkn4miNoinG60Ynbsp1JkU8tAVKy4v8HUBLictAg==",
}

// Windows_5_0_0_qa_74_15_1683039954 is Windows 5.0.0-qa-74-15, build 1683039954.
var Windows_5_0_0_qa_74_15_1683039954 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-15 [Build: 1683039954]",
	Sign:     "MFemYXY5GGg2OYhdRzdhpkn9ujzOMMCZA8QGlPV1GUbhjjtjXuMw5+ydEzLwcgZYpFTod3N6CEz/b/aXwWeyCQ==",
}

// Windows_3_6_0_1683203743 is Windows 3.6.0, build 1683203743.
var Windows_3_6_0_1683203743 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1683203743]",
	Sign:     "Ha73fVhy6+r06Zh3CCx8RVJ1HtHCaABNnTfFbjQPy0dm/e79JFIPZgeC5IvJBltwaiBic/9M+aKBrt+7sNxNDw==",
}

// Linux_3_6_0_1683203743 is Linux 3.6.0, build 1683203743.
var Linux_3_6_0_1683203743 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1683203743]",
	Sign:     "ao52xPYBI8qe57kJJ6KQgQPr0J9w7BhGikkFMqs7pGpsrxLK9ghzOlbu5IZsdct3tNw88S2YB0oFmcCWlx+hCA==",
}

// OSX_3_6_0_1683203743 is OS X 3.6.0, build 1683203743.
var OSX_3_6_0_1683203743 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.0 [Build: 1683203743]",
	Sign:     "w/rKVPUul3im2KxVqvL8udZf/o0Yre+92bvACj8hU1x5aNtQkvodXo7CML+4mM6EgifiVCyI8kyo6BtbfeF7Ag==",
}

// Windows_5_0_0_qa_74_17_1683295507 is Windows 5.0.0-qa-74-17, build 1683295507.
var Windows_5_0_0_qa_74_17_1683295507 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-74-17 [Build: 1683295507]",
	Sign:     "hpDc2gHUCHv3HUA1nBray8U8Re/d9XvDUHZkefwMkgeL8L6KizWeo7vZzFguQLYpRPr20B4h0d/A8NAxYxfqAA==",
}

// Windows_5_0_0_beta74_1683627550 is Windows 5.0.0-beta74, build 1683627550.
var Windows_5_0_0_beta74_1683627550 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta74 [Build: 1683627550]",
	Sign:     "pipm1uaijQDJKPZgRkhjyLsLG/W9KnjEDWNGvqUkUrSuqrUvfEG4OUsdTOReMb+FJp4xz82n3cwd4HExO5k3Dw==",
}

// Linux_5_0_0_beta74_1683627550 is Linux 5.0.0-beta74, build 1683627550.
var Linux_5_0_0_beta74_1683627550 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta74 [Build: 1683627550]",
	Sign:     "M5TTHH2J1erTQKBElj0dz4Lm9N4erZuHxZNjNlbJjDxRC8CYnziveIW0j8DY8NeQaSKHeCTXoL5pDakZtvAODQ==",
}

// MacOS_5_0_0_beta74_1683627550 is macOS 5.0.0-beta74, build 1683627550.
var MacOS_5_0_0_beta74_1683627550 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta74 [Build: 1683627550]",
	Sign:     "EmwreqEhVhmpGrjPKyNjwuEdWKF+uGTX0syXkq57+klgtcNw9lddPm9lodLTdB5spPGlsx0CJQySvEXlWyXNDg==",
}

// Windows_5_0_0_qa_tr_1_1683731563 is Windows 5.0.0-qa-tr-1, build 1683731563.
var Windows_5_0_0_qa_tr_1_1683731563 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-tr-1 [Build: 1683731563]",
	Sign:     "HmBOKipdW28prdI2FFdmBu/mMXui+zdC0G7769F3bW+nVRfNoVtvJhSUx7/UDeQ9ghHbUIW6q2lCxnQLzsIRCg==",
}

// Windows_3_6_0_1683804569 is Windows 3.6.0, build 1683804569.
var Windows_3_6_0_1683804569 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1683804569]",
	Sign:     "PesaPHU3+aiZMUPzpq8UBKjck77jLw9N+hyZq6JjD4baqns5dmKj4sTfSL9/QROyOLqPICZ+fwkSy5iuuMQEAw==",
}

// Linux_3_6_0_1683804569 is Linux 3.6.0, build 1683804569.
var Linux_3_6_0_1683804569 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1683804569]",
	Sign:     "CqbjoDdeYd83t/u9YUtlQf4rDIf6yEnFInF6nq7GcO02tRXBQlppxHd/ziaTdlpwYrha00goKb2GGWwdrNhFAA==",
}

// OSX_3_6_0_1683804569 is OS X 3.6.0, build 1683804569.
var OSX_3_6_0_1683804569 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.0 [Build: 1683804569]",
	Sign:     "sT6ej/41Qk3T0LfXl3+VSm3J7Ck4M/OCTWIRundvOHBRodGLWJtddZuQu7IlXNr9mbJfklarQ4XyyXvXMdjvCw==",
}

// Windows_5_0_0_qa_75_1_1684855710 is Windows 5.0.0-qa-75-1, build 1684855710.
var Windows_5_0_0_qa_75_1_1684855710 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-1 [Build: 1684855710]",
	Sign:     "LLfl5sHAfsdepvecADQI9/nx98H+jA/r9pe6fq5CqlRY+MCdVbOphiXy7zZerE5h4lIRqcJtEeAJVIXaNu+LDA==",
}

// Windows_5_0_0_qa_75_2_1685542148 is Windows 5.0.0-qa-75-2, build 1685542148.
var Windows_5_0_0_qa_75_2_1685542148 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-2 [Build: 1685542148]",
	Sign:     "Ir/0IAdrK5dDVDlh6gIRwGZe0DFR9vUNf313cLwHTN1EB9nyO2Bq5yoBjZuGYOdNgcbdgQCBzfKNd4ZpCxxSAg==",
}

// OSX_3_6_0_1685546268 is OS X 3.6.0, build 1685546268.
var OSX_3_6_0_1685546268 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.0 [Build: 1685546268]",
	Sign:     "i257nbRzdfvBvgW4IeFoCe8KnCDfoIvtNeORVFVPohKWfFajfoBNYTDa/2/jgHbd97Dzqd+hx8t2ZwPPwgR+Bg==",
}

// Windows_5_0_0_beta75_rc1_1685698093 is Windows 5.0.0-beta75-rc1, build 1685698093.
var Windows_5_0_0_beta75_rc1_1685698093 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc1 [Build: 1685698093]",
	Sign:     "Jkvyb0PGEmS3/lVfr2x7SFlSZMeopxo7JXBHx8m1pWeDL7XdjYoDPOaIJ6UD1hNxY/wv84fgAwt65Ip2AdP1Dw==",
}

// Windows_5_0_0_beta75_rc2_1686050172 is Windows 5.0.0-beta75-rc2, build 1686050172.
var Windows_5_0_0_beta75_rc2_1686050172 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc2 [Build: 1686050172]",
	Sign:     "BcULgPFoo2+QTsjD88VH5rONZcABm32fgd5jBNbdkxTaERND/CJI4ZBWS30s5WKN9bi3T6LKUOzcLyN6+gfNDQ==",
}

// Windows_5_0_0_beta75_rc3_1686126230 is Windows 5.0.0-beta75-rc3, build 1686126230.
var Windows_5_0_0_beta75_rc3_1686126230 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc3 [Build: 1686126230]",
	Sign:     "1Jj8VSZ8QQ2K5jFiRM2DB6Z12Yi1fFjJ3ng96W/S+zU2VzldrOsuvhO36BOjbWMCcEIWoc45sbHPm+utJtxeAw==",
}

// MacOS_5_0_0_beta75_rc3_1686126230 is macOS 5.0.0-beta75-rc3, build 1686126230.
var MacOS_5_0_0_beta75_rc3_1686126230 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta75-rc3 [Build: 1686126230]",
	Sign:     "38gec16GTEPCeaVw5qM8tU58HWM0HZ20yROR1foT8TRHqsTvoED2gm07xb6KfSHN3//3k1ErMvuS4emNBohcBA==",
}

// Windows_3_6_0_1686637110 is Windows 3.6.0, build 1686637110.
var Windows_3_6_0_1686637110 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1686637110]",
	Sign:     "r21r7w+EGu6F6aruzYiuzv2lP5bX8X4TP2xXBH5Wljz3x/VxOxndN84qA9sPn6QJZFQCtzq+iEb0wfFFM7mYCA==",
}

// Linux_3_6_0_1686637110 is Linux 3.6.0, build 1686637110.
var Linux_3_6_0_1686637110 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1686637110]",
	Sign:     "8eM1WF1E9+8DeS+Zm6IcidGtuTC0+jtrLRkkiIk+GUA91bVOCyYgrUWNFVftZtFEM4qIOICJhLQopVTIwYJOCQ==",
}

// Windows_3_6_0_1686731472 is Windows 3.6.0, build 1686731472.
var Windows_3_6_0_1686731472 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1686731472]",
	Sign:     "KRYqAaQhnKh/NQ4LrOw8+nVA659NDn+IlOB8hhmKZolIOEDSiijCeDoTVf61t/0Z0y1OWlxABS4X7uWRzvhiDw==",
}

// Linux_3_6_0_1686731472 is Linux 3.6.0, build 1686731472.
var Linux_3_6_0_1686731472 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1686731472]",
	Sign:     "MKaey6yCAdQDBHl5ERY24N5bz9CsdypGJfpTC5mNPc0s3Z1zeb8c3g9/w/mlRD+qoK3xlCYt3f25oaFMZofMAA==",
}

// Windows_3_6_0_1686736529 is Windows 3.6.0, build 1686736529.
var Windows_3_6_0_1686736529 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1686736529]",
	Sign:     "kRHYyNCdM5rna2v27LyPerCeNd1s76h0KfpLSmLQk3Bzkrg/NCBzpj0WofE1cvbQ2Qm/41d/mUIMxIfXJ/+hCg==",
}

// Linux_3_6_0_1686736529 is Linux 3.6.0, build 1686736529.
var Linux_3_6_0_1686736529 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1686736529]",
	Sign:     "l1LIP8nreS+y33Hp7SmA6M7kJZZI1KbsN1/Rx9hAAL3Wd6PbEwhLIQHXBkfCI8MizWSAl7NDb+UOuNxAL9GoAg==",
}

// OSX_3_6_0_1686736529 is OS X 3.6.0, build 1686736529.
var OSX_3_6_0_1686736529 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.0 [Build: 1686736529]",
	Sign:     "EFU7gHd4QZhwmAojg0Tk/tL9dPiFTcWn40R/6YZCrlzX6t0FSPXiAj93OUf1du+qyy2ly4Lrox/M0u4wOhEDBg==",
}

// Windows_3_6_0_1686744367 is Windows 3.6.0, build 1686744367.
var Windows_3_6_0_1686744367 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1686744367]",
	Sign:     "VXx9yKF0ZaBMqlU285hPLxaCgH1N8OwKjU52A0EdulFmEeLYYQeJI/7139hno0Ph8kGT6nxoDRKtw0yn9woNAQ==",
}

// Linux_3_6_0_1686744367 is Linux 3.6.0, build 1686744367.
var Linux_3_6_0_1686744367 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1686744367]",
	Sign:     "toUkg41DTfeCfWgqqxSeb8eDzri2PsjRNIcHsFxr0d7nLCTYGoSFfQjme84FjMYtvYloMVAk/gx5Nt+hWE+ZBg==",
}

// Windows_3_6_0_1686749764 is Windows 3.6.0, build 1686749764.
var Windows_3_6_0_1686749764 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.0 [Build: 1686749764]",
	Sign:     "gfzG6CfwNYeqrjT68s7ahPd24A/XS0P8LLAB7hrE54MnrlO12RiflD2w69VZ7EYlqnd9GAiVzdGJHCmCFWtlAQ==",
}

// Linux_3_6_0_1686749764 is Linux 3.6.0, build 1686749764.
var Linux_3_6_0_1686749764 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.0 [Build: 1686749764]",
	Sign:     "TccRBHwn5LSA0lfpa2B42QmfCOiG+MqqyhlOqy5RcuRQNUGPD0e47lUz+Z/8+Gsdc1TPG4+vYlRl8+v2v+26Aw==",
}

// OSX_3_6_0_1686749764 is OS X 3.6.0, build 1686749764.
var OSX_3_6_0_1686749764 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.0 [Build: 1686749764]",
	Sign:     "g8H7Op8eCrn0wHutuD/SlmUcZPmkSlFUBhvZpSgm9kuQl4dapzKJq2anI5jDwRs/ooBm/wrIlSiWI6HXuOPZDA==",
}

// Windows_5_0_0_beta75_rc4_1687777367 is Windows 5.0.0-beta75-rc4, build 1687777367.
var Windows_5_0_0_beta75_rc4_1687777367 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc4 [Build: 1687777367]",
	Sign:     "wIGrljvdCMZX3XJoe0rWTA/nNZuXVC6z8kUvDw1gi9YxyM6AxmsleqOzjZ3zY5Ii7cRU8slxNAh4ERLcHEPQDg==",
}

// Linux_5_0_0_beta75_rc4_1687777367 is Linux 5.0.0-beta75-rc4, build 1687777367.
var Linux_5_0_0_beta75_rc4_1687777367 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta75-rc4 [Build: 1687777367]",
	Sign:     "DCZXmwc6xocEuzvS+f+qyQLwN8FLdNqyDTAjdOfy1y8JeO8VmIlNwRFd7X0D0Q51kqPNPIB7Jbh4yiwySHjhDw==",
}

// MacOS_5_0_0_beta75_rc4_1687777367 is macOS 5.0.0-beta75-rc4, build 1687777367.
var MacOS_5_0_0_beta75_rc4_1687777367 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta75-rc4 [Build: 1687777367]",
	Sign:     "xgV8yX/XS3qVXshur/PbsquRIbPvz3w+hJL905nQQBwbniSGvKxAUcTJompBgECG989hf6nW+2GApbf8p70RBw==",
}

// Windows_5_0_0_beta75_rc5_1687944933 is Windows 5.0.0-beta75-rc5, build 1687944933.
var Windows_5_0_0_beta75_rc5_1687944933 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc5 [Build: 1687944933]",
	Sign:     "1fQu13pX9jdR5oJ4yaqasfoWrcySvwocstrOQOZLZjB+0nUtKMYW4Kp2DYHuIoTlvuWiiF7pYc7YK4bOUWdlAA==",
}

// Windows_3_6_1_1689766945 is Windows 3.6.1, build 1689766945.
var Windows_3_6_1_1689766945 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.1 [Build: 1689766945]",
	Sign:     "+6Tcswj4E40ablTifyXIA3UDEY+359hxjEVx+Tb+xha08CiSwpzSpFndS8GCs8z0QICVKUZBwhVfGfePm00vDw==",
}

// Linux_3_6_1_1689766945 is Linux 3.6.1, build 1689766945.
var Linux_3_6_1_1689766945 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.1 [Build: 1689766945]",
	Sign:     "fjR+/+EsahBSG/qGjcTTUVIyn/w7W6h7uy9YUebYzRbtWIxxv69ZD4k7Y4Z1OS9+cuB/Nbtg05J2Upt2oK/qCg==",
}

// Windows_3_6_1_1689949736 is Windows 3.6.1, build 1689949736.
var Windows_3_6_1_1689949736 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.1 [Build: 1689949736]",
	Sign:     "30JdFX5zLrHx3uKsb55vpdlS6DO36bVRSOewzOlTV70LS4X0dVMZp64EzDZY8ZR2woAAjZ8ZR/rIKt4JlNnKDg==",
}

// Linux_3_6_1_1689949736 is Linux 3.6.1, build 1689949736.
var Linux_3_6_1_1689949736 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.1 [Build: 1689949736]",
	Sign:     "yM9tjby+KBrov9dyNLM1I1PZXDBK2fdwR8ylvKdZJc/DaL5GqnoBAGLkFmzOIl//u8VMbXspCDWb/PbvOS2gAg==",
}

// Windows_3_6_1_1690193193 is Windows 3.6.1, build 1690193193.
var Windows_3_6_1_1690193193 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.1 [Build: 1690193193]",
	Sign:     "I5uwVK2CZa9aXblVQPUKGbjNYoE2eaUPujK8sVGWAUsPhmGySTvSkP70jrpX8pUgQdtHwUOl3gvrAH6+moNeDQ==",
}

// Linux_3_6_1_1690193193 is Linux 3.6.1, build 1690193193.
var Linux_3_6_1_1690193193 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.1 [Build: 1690193193]",
	Sign:     "UAcE5h5FgPcdChWTtiO816HX8f2qdoDcDEw6crbJ96Yo7rp1Bt+qx/rkKK9bzlVWMhOd4fI7pr++1XaPkEBnAQ==",
}

// OSX_3_6_1_1690193193 is OS X 3.6.1, build 1690193193.
var OSX_3_6_1_1690193193 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.1 [Build: 1690193193]",
	Sign:     "P+KOw42V8K0nN5FbGItCaJzrDuWcRgfE3MRzrtbYAhRMTXHzRxvwLkoLM7+vKTW135NtWZlKbZuDAvxgwhSLBg==",
}

// Windows_5_0_0_beta75_rc7_1690443874 is Windows 5.0.0-beta75-rc7, build 1690443874.
var Windows_5_0_0_beta75_rc7_1690443874 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc7 [Build: 1690443874]",
	Sign:     "dvpImL6c5RMVxPV/jNNG3DncR8QlQcqWKBQCDiE89KQpZ/q4kRJkAlje0Pgoqk8BT/2WQWaUixqctfOGNPxNBA==",
}

// Windows_3_6_1_1690811573 is Windows 3.6.1, build 1690811573.
var Windows_3_6_1_1690811573 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.1 [Build: 1690811573]",
	Sign:     "aWKpb0eAiI6FndcOBw+OixzripgCENMlM5gwKuRhdqtOdWAEYI5Luz8sGQ77yWC1RlQ1llxHcqhjNcJ8qMVcAw==",
}

// Windows_3_6_1_1690872913 is Windows 3.6.1, build 1690872913.
var Windows_3_6_1_1690872913 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.1 [Build: 1690872913]",
	Sign:     "+YmPaYUBL4F9+TgxyFhlT8qIi1Ym+So4NNMcuohla/u4kfJCGabZ1vDF4cIOAghIqWfO+bQ0OkORZrCBdpi2Cw==",
}

// Windows_5_0_0_beta75_rc8_1690875928 is Windows 5.0.0-beta75-rc8, build 1690875928.
var Windows_5_0_0_beta75_rc8_1690875928 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc8 [Build: 1690875928]",
	Sign:     "1xI3XWPzHxz5zD4OIZDvJteHXOHcxliqCGh/lifvzA6Gb+/GhkcPGj5RqmlIHPKHJFAozbB0UhvTuJcTU5HGDg==",
}

// Windows_5_0_0_qa_75_4_1690964581 is Windows 5.0.0-qa-75-4, build 1690964581.
var Windows_5_0_0_qa_75_4_1690964581 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-4 [Build: 1690964581]",
	Sign:     "3o5M5JegEvtXwGHMdhUSR+PbaXTIoinUI1GGgoXrGi2tYNUvaguiYYlsak4z8twpgzp68L0KaoA4nz4DyNX9Aw==",
}

// Windows_3_6_2_1690976575 is Windows 3.6.2, build 1690976575.
var Windows_3_6_2_1690976575 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.2 [Build: 1690976575]",
	Sign:     "OyuLO/1bVJtBsXLRWzfGVhNaQd7B9D4QTolZm14DM1uCbSXVvqX3Ssym3sLi/PcvOl+SAUlX6NwBPOsQdwOGDw==",
}

// Linux_3_6_2_1690976575 is Linux 3.6.2, build 1690976575.
var Linux_3_6_2_1690976575 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.2 [Build: 1690976575]",
	Sign:     "iSJZ2tmUsUhCuB3G/7SCgM+JNZe3Jb/KSxFNr+0FDgg8r5t4JKGBD0SPl/cdDMqNqXmG9zEHi0XmuVl9lysoCg==",
}

// OSX_3_6_2_1690976575 is OS X 3.6.2, build 1690976575.
var OSX_3_6_2_1690976575 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.2 [Build: 1690976575]",
	Sign:     "0VegJZtWI25+RXM3J6jNfskqEgM8f4CyYrrz0IXuSK8azRQ3AMWH7YgSnrotoIX1q7aDhnTulk9eChKSPoKVCQ==",
}

// Windows_5_0_0_qa_75_8_1691162334 is Windows 5.0.0-qa-75-8, build 1691162334.
var Windows_5_0_0_qa_75_8_1691162334 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-8 [Build: 1691162334]",
	Sign:     "yLHN6dcol32mrRoi2ZMYDYsn9XPMncp79PwcCHxFC+8CuaxhOSq7/iXUPwhsdqvUQzyvstq1hCaG9/MLn8G/Dg==",
}

// MacOS_5_0_0_qa_75_8_1691162334 is macOS 5.0.0-qa-75-8, build 1691162334.
var MacOS_5_0_0_qa_75_8_1691162334 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-qa-75-8 [Build: 1691162334]",
	Sign:     "jJLCUYbKDDtPB56YGtUSK+EjrY3LxoOAWVLHKIc/Li4UAFNL9iaq5gRvHF+cfJHyGg0keg2SEVr1+TfCEDG4Dw==",
}

// Windows_5_0_0_beta75_rc10_1691405422 is Windows 5.0.0-beta75-rc10, build 1691405422.
var Windows_5_0_0_beta75_rc10_1691405422 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc10 [Build: 1691405422]",
	Sign:     "ETFP63u2QoQzmb1vHyRC+KxAAZKWq1PEpKfC6ep8A59zptnOtocEbc50wb55GpF7pVv2n5nJP6CV3iv2QauAAA==",
}

// Windows_5_0_0_qa_75_9_1691734909 is Windows 5.0.0-qa-75-9, build 1691734909.
var Windows_5_0_0_qa_75_9_1691734909 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-9 [Build: 1691734909]",
	Sign:     "t0guTMT1lZZI34At9X9kg0/ablk2LEtjePCLXNSCyTGeam3E4l+hjjaLZYx5gFLDX4tQEGqG4Dms96T+xRVTCg==",
}

// Windows_5_0_0_qa_tr_2_1691758984 is Windows 5.0.0-qa-tr-2, build 1691758984.
var Windows_5_0_0_qa_tr_2_1691758984 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-tr-2 [Build: 1691758984]",
	Sign:     "YmsBwLBmFqrMhlCLGXUcn/qLvHJBrOeg1kRj+xDp7FltLJ6z4G5r6QdPt1sTaalD3TWE9If10i9mQFnP73nCDw==",
}

// Windows_5_0_0_beta75_rc11_1692269983 is Windows 5.0.0-beta75-rc11, build 1692269983.
var Windows_5_0_0_beta75_rc11_1692269983 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc11 [Build: 1692269983]",
	Sign:     "TraubtepmvLTzCkyZwDgJram2qrdpuPy1hWRhN0ZFwSAnXkBklJjBSMAUO22D/hTAfTeiQaUiFDJThf2aGSJBQ==",
}

// Windows_5_0_0_beta75_rc12_1692273792 is Windows 5.0.0-beta75-rc12, build 1692273792.
var Windows_5_0_0_beta75_rc12_1692273792 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc12 [Build: 1692273792]",
	Sign:     "fX3auh0DNxFmMmmjKmxJ0bS5T+sI2OActVkppSthJOJ/W1so/WfdxtxavuJgpzFHQ7wqanaJYUajAY0uFnYEDA==",
}

// Linux_5_0_0_beta75_rc12_1692273792 is Linux 5.0.0-beta75-rc12, build 1692273792.
var Linux_5_0_0_beta75_rc12_1692273792 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta75-rc12 [Build: 1692273792]",
	Sign:     "UFodfOKNy4uOGnQdL35xlc5XoOkT2xVzn93w2+rshfBQKd63BqCqBcrMDL5We4UGnCdeF7oiUsraWm65qvfDDA==",
}

// MacOS_5_0_0_beta75_rc12_1692273792 is macOS 5.0.0-beta75-rc12, build 1692273792.
var MacOS_5_0_0_beta75_rc12_1692273792 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta75-rc12 [Build: 1692273792]",
	Sign:     "yRtBZtJrOetbT3IREKlZ7bYCLLDWtl88l6OvbRHsfI0MwgBuaLuZmgA7gAGaNDc4u427XpxD1U4WRRMJ4XXuCA==",
}

// Windows_5_0_0_qa_75_10_1692281089 is Windows 5.0.0-qa-75-10, build 1692281089.
var Windows_5_0_0_qa_75_10_1692281089 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-10 [Build: 1692281089]",
	Sign:     "6Tn50hZBDK2v1gAfXvnfVsOvCYiZ5O7t9ae/PGIzTQPYJiK+83CCR9F+NrjaNwrwn8U4fHCm0DvF2qrk6FiEDA==",
}

// Windows_5_0_0_qa_75_11_1692344346 is Windows 5.0.0-qa-75-11, build 1692344346.
var Windows_5_0_0_qa_75_11_1692344346 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-11 [Build: 1692344346]",
	Sign:     "XUiXiYpVQ1lvhscQ0T0STLhzFxgUgPD5yRvHnHa+gl0z62xvSnUYMcaulZu+vu7N7Zx2XD0yXwDt1aAWjmSmAQ==",
}

// Windows_5_0_0_qa_75_12_1692942703 is Windows 5.0.0-qa-75-12, build 1692942703.
var Windows_5_0_0_qa_75_12_1692942703 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-12 [Build: 1692942703]",
	Sign:     "eg20cqWFjsdIv3fP37BPzSsEMAabdXgPwE/iZ0nu8JIUFCx+dDPmD+Yezf4f2cbe+w7MEkPoAMKS5cAOYbG9BQ==",
}

// Windows_5_0_0_qa_tr_4_1692956820 is Windows 5.0.0-qa-tr-4, build 1692956820.
var Windows_5_0_0_qa_tr_4_1692956820 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-tr-4 [Build: 1692956820]",
	Sign:     "B8tNlJlgST8ITvDXO4m0mBmR+fOur02Dr0MbmYcE1LWOWJfQUk2A5Lyni65NEBdJIg6/D3ihc0US27Yd4sFWAA==",
}

// Windows_5_0_0_qa_75_14_1693548790 is Windows 5.0.0-qa-75-14, build 1693548790.
var Windows_5_0_0_qa_75_14_1693548790 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-14 [Build: 1693548790]",
	Sign:     "eBIeiZ9RjIlTT9AVkwXsiHsKrvSkGWfILDbts+A5xGDsIU8nFGl77uXjfNqjM6+Ud2Eb6lKk7NVQrmRWs/b7AQ==",
}

// Linux_5_0_0_qa_75_14_1693548790 is Linux 5.0.0-qa-75-14, build 1693548790.
var Linux_5_0_0_qa_75_14_1693548790 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-qa-75-14 [Build: 1693548790]",
	Sign:     "VFo+uqfuN636vfO2uplN7MxwjcGgZ7C7a8H78PSMBtPYU5KOh86FNgH3g4TefK5suVza384d9DpPK5sjZBVICA==",
}

// Windows_5_0_0_qa_tr_6_1693832989 is Windows 5.0.0-qa-tr-6, build 1693832989.
var Windows_5_0_0_qa_tr_6_1693832989 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-tr-6 [Build: 1693832989]",
	Sign:     "IOoZZnLdprCn572p0GRdOJftjQq12pYODanfyqFy9rG+sSQWmDs4Q7LX5aF/K6oRi1dj31I/BaBKxRhcs0ylAQ==",
}

// Linux_5_0_0_qa_tr_6_1693832989 is Linux 5.0.0-qa-tr-6, build 1693832989.
var Linux_5_0_0_qa_tr_6_1693832989 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-qa-tr-6 [Build: 1693832989]",
	Sign:     "7S96m1KKKlB2+x4osdky+gdCUnWTlAaoiOQcsmmXPUxxyS/ypTY7tnYRmo2lj/Hx46aI7R0+Z4+vnHLIY9InCw==",
}

// Windows_5_0_0_qa_75_16_1694525079 is Windows 5.0.0-qa-75-16, build 1694525079.
var Windows_5_0_0_qa_75_16_1694525079 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-16 [Build: 1694525079]",
	Sign:     "mnve3nHnNHCWJD/v1UucjHwYP5iiMcQYozzkQTxY4SlU3HozJb1Zkq9hhXpnaQHE37TODB+7B/fshVo/yWJIAA==",
}

// Windows_5_0_0_qa_75_17_1694593665 is Windows 5.0.0-qa-75-17, build 1694593665.
var Windows_5_0_0_qa_75_17_1694593665 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-17 [Build: 1694593665]",
	Sign:     "dQxRWH4A/RdhuwMQG2fWtbP8aRLJNs9eGrdSHBEd07MEVA29iyNx6J4Ab9pFvzw8rbxC/QsL20G1LGc0ilz7Dg==",
}

// Windows_5_0_0_qa_75_18_1694615531 is Windows 5.0.0-qa-75-18, build 1694615531.
var Windows_5_0_0_qa_75_18_1694615531 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-18 [Build: 1694615531]",
	Sign:     "qDBmGwpP/bskv03tvqCDvK4xXGVpyS7K6cvu06/yMk5rDd05Dba928UfMNh0/Wub/Xy9MfI5gVdA3kSuXJrnDA==",
}

// Windows_5_0_0_qa_75_19_1694699313 is Windows 5.0.0-qa-75-19, build 1694699313.
var Windows_5_0_0_qa_75_19_1694699313 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-75-19 [Build: 1694699313]",
	Sign:     "KtR3EavFC3d5PBcKFWt7Gd27B6fAG0k4EevugDzjYs2BCg+PFgeZ1DPAQCw8/k0SzewR7i9x/ZedhPC7pvYmDA==",
}

// Windows_3_6_2_1695203293 is Windows 3.6.2, build 1695203293.
var Windows_3_6_2_1695203293 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.2 [Build: 1695203293]",
	Sign:     "4BdaZpdgUSMCuIs8qcloJPNxNlJ4o7QKnxMCRO60mSOTtJZyKjOrGLAmeAEtLIJjcjmdSpycMbQOIV92K2vXAw==",
}

// Linux_3_6_2_1695203293 is Linux 3.6.2, build 1695203293.
var Linux_3_6_2_1695203293 = ClientVersion{
	Platform: "Linux",
	Version:  "3.6.2 [Build: 1695203293]",
	Sign:     "p4iF1jZ3ZOz9MEkKSZ2bvnFtm9WmUcQy9mAP//erFE4PF1sB6K1CSANrr+3X4B0aZR0u+K2pjnv8kiKsWKQCBQ==",
}

// OSX_3_6_2_1695203293 is OS X 3.6.2, build 1695203293.
var OSX_3_6_2_1695203293 = ClientVersion{
	Platform: "OS X",
	Version:  "3.6.2 [Build: 1695203293]",
	Sign:     "SOCkLcsxINIGVc+3OQ5Vrmv2BVNNFA9LX5Jj9tqbIiYv2HU6Z5E8AL5+v5G2LDN0F+U55+uW43ezUoYAr1WuBA==",
}

// Windows_5_0_0_beta75_rc13_1695397203 is Windows 5.0.0-beta75-rc13, build 1695397203.
var Windows_5_0_0_beta75_rc13_1695397203 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc13 [Build: 1695397203]",
	Sign:     "dSkrQtjUjxOQmAdQUbi7Z6oQFKPqi6/nsKVpovncQ4hDjQqVsUfoS2NO/XHO+iCwH0De3zrPgPQju3bRiYdzBA==",
}

// MacOS_5_0_0_beta75_rc13_1695397203 is macOS 5.0.0-beta75-rc13, build 1695397203.
var MacOS_5_0_0_beta75_rc13_1695397203 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta75-rc13 [Build: 1695397203]",
	Sign:     "gwgeaGifMO1IIGcPJBbHUklR0m11N+XeuvflfT5CFUh0RE3zbzmV0ehUtg5udX9BU9XxcLh5LsiMQtmUobmUCQ==",
}

// Windows_5_0_0_beta75_rc14_1696088917 is Windows 5.0.0-beta75-rc14, build 1696088917.
var Windows_5_0_0_beta75_rc14_1696088917 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc14 [Build: 1696088917]",
	Sign:     "GoQG+71nd6b9QUv7vECPDAXGcKEWwrW/YbPaQVNhdFwonbKegBPYKUel8rxuGzqR/uJp3EqXEGV0JyQBVXiEBg==",
}

// Windows_5_0_0_beta75_rc14_1696489500 is Windows 5.0.0-beta75-rc14, build 1696489500.
var Windows_5_0_0_beta75_rc14_1696489500 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75-rc14 [Build: 1696489500]",
	Sign:     "6rCkYTY/IQav+zwrXfu9wFEmeuFcNxuHKBdW5aiblX5a0KpF9wzn0qwwKgjZcrzQiH5+r9tmsoB36KSwdxX1Dg==",
}

// Windows_5_0_0_beta75_1696607978 is Windows 5.0.0-beta75, build 1696607978.
var Windows_5_0_0_beta75_1696607978 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta75 [Build: 1696607978]",
	Sign:     "0LhX3/Ss9GxjzXzyW6sNvaIGtivWocu9CDH3k0tOqkm8rjiwwQFTu3dCtGEzgBw89QrCXEcKOmZkbgLpechOAg==",
}

// Linux_5_0_0_beta75_1696607978 is Linux 5.0.0-beta75, build 1696607978.
var Linux_5_0_0_beta75_1696607978 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta75 [Build: 1696607978]",
	Sign:     "zk+WtkzXgRWAFIA59ad066AbGsom9QfQW6JpskztbEh4Gri5BlsQ/HKy2xUfQX+7x+A1ukt27BU/6msK7B5bAA==",
}

// MacOS_5_0_0_beta75_1696607978 is macOS 5.0.0-beta75, build 1696607978.
var MacOS_5_0_0_beta75_1696607978 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta75 [Build: 1696607978]",
	Sign:     "W9THGtchSxG8Q9DmjC72Ah5wcWVH9/+ZxTH3TZKH3E3NsyjaRwMdjgPvfYVaOb3qYq8Se/HxkYqBbyxSJZFBBg==",
}

// Windows_5_0_0_beta76_rc1_1697033899 is Windows 5.0.0-beta76-rc1, build 1697033899.
var Windows_5_0_0_beta76_rc1_1697033899 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta76-rc1 [Build: 1697033899]",
	Sign:     "CLEscmKTzIkTC9VAQAQ1hIN6eOlSaOjuaWE8EqYThv0aunDzxWRBG9MCNQmdLJ8JgtIM6Ng412x46TOoGAmJBg==",
}

// MacOS_5_0_0_beta76_rc1_1697033899 is macOS 5.0.0-beta76-rc1, build 1697033899.
var MacOS_5_0_0_beta76_rc1_1697033899 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta76-rc1 [Build: 1697033899]",
	Sign:     "ZjuTP89K3fFgfAHkzg9vbhR+EkSOnkozd1pTXB2MH//jTj9tfyEPwDlzK1TaCV+JKoAsM5WlSmyx//a72S7mDQ==",
}

// Windows_5_0_0_beta76_rc5_1697802195 is Windows 5.0.0-beta76-rc5, build 1697802195.
var Windows_5_0_0_beta76_rc5_1697802195 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta76-rc5 [Build: 1697802195]",
	Sign:     "5JXHvuwisq+an9hsgGgA6FW00ENcH5khuMQ1SFyaKgKdByDdvPA7/XbPtxRvUvSUh5brGL4m3CldEQ88ga1mCw==",
}

// MacOS_5_0_0_beta76_rc5_1697802195 is macOS 5.0.0-beta76-rc5, build 1697802195.
var MacOS_5_0_0_beta76_rc5_1697802195 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta76-rc5 [Build: 1697802195]",
	Sign:     "0aSd/h3YrLvyhywBXtNf2h1ZfSLkHW3jr33EoIsuL6oBepMSvi0nZI3Gx8j4gmLDXtwxE9+wFqrm2vc5VfYjCQ==",
}

// Windows_5_0_0_beta76_1698243642 is Windows 5.0.0-beta76, build 1698243642.
var Windows_5_0_0_beta76_1698243642 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta76 [Build: 1698243642]",
	Sign:     "zV72PUBNtH7bblwdldd6t/o8hprjepbfR7CbzQCehaYUTID5y/W4IW7e/Qt4v9ip55mycWzADgiqCndMlOVNDA==",
}

// Linux_5_0_0_beta76_1698243642 is Linux 5.0.0-beta76, build 1698243642.
var Linux_5_0_0_beta76_1698243642 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta76 [Build: 1698243642]",
	Sign:     "xXggpgd8+q2Ozk/of+0ciH2v/jp1K83EorMbbiI/J6ywpzQVocFyqQUpOjD6Xoh6K2AV2heFQF/cKoJ0aHwABA==",
}

// MacOS_5_0_0_beta76_1698243642 is macOS 5.0.0-beta76, build 1698243642.
var MacOS_5_0_0_beta76_1698243642 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta76 [Build: 1698243642]",
	Sign:     "Buhg/MoJF/pPldGEsesBUpTj+ClIp4xFXX/n+BcOgIS98D/kdO8pTWbk42f+wx24ALEJRwWZCYunaLFXF0iJDA==",
}

// MacOS_5_0_0_qa_77_1_1698316110 is macOS 5.0.0-qa-77-1, build 1698316110.
var MacOS_5_0_0_qa_77_1_1698316110 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-qa-77-1 [Build: 1698316110]",
	Sign:     "ESRePbVvFOl0wUJKoSsFAMV34isnFNfzvUQW6yDoMqa8GNGNPdRw10TxUA+ypTzu4H3A8VEiKgEEm2pdwj/5CA==",
}

// Windows_5_0_0_beta77_1699457285 is Windows 5.0.0-beta77, build 1699457285.
var Windows_5_0_0_beta77_1699457285 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta77 [Build: 1699457285]",
	Sign:     "id8cERxgKG68YRDcSYCceqekamIZlBmAE/IfwYkpu+a8RC0Gkyyhtn4ZU80ppUfES3GFsGVSSwJ/eci1g+pCBg==",
}

// Linux_5_0_0_beta77_rc1_1700224895 is Linux 5.0.0-beta77-rc1, build 1700224895.
var Linux_5_0_0_beta77_rc1_1700224895 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta77-rc1 [Build: 1700224895]",
	Sign:     "T101xCL/zRr+iwZJHURKd4DUDTrQSSJ3QsADpMH/Ed8wqXPTqneP6hQk04tKEB39aJCJTDW9W0FT7Pf7vCKLBA==",
}

// MacOS_5_0_0_beta77_rc1_1700224895 is macOS 5.0.0-beta77-rc1, build 1700224895.
var MacOS_5_0_0_beta77_rc1_1700224895 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta77-rc1 [Build: 1700224895]",
	Sign:     "0y/hKU/yqkqgUqtn6KXbuRtqQa4DlYQ50Rziwg9k4wAUgAnCm1hts7AvUHrGv5415cJX9czxUAFdIEApPR06CA==",
}

// Windows_5_0_0_beta77_rc2_1700761919 is Windows 5.0.0-beta77-rc2, build 1700761919.
var Windows_5_0_0_beta77_rc2_1700761919 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta77-rc2 [Build: 1700761919]",
	Sign:     "VOTBvsWNSc5MNXDWd/M3JpCB8WzvUlj7+V7EVtUy9cZ8LaK8TyJjIip16YJnVDod73wMW8npyt4oaDrqkzL6Bg==",
}

// Linux_5_0_0_beta77_rc2_1700761919 is Linux 5.0.0-beta77-rc2, build 1700761919.
var Linux_5_0_0_beta77_rc2_1700761919 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta77-rc2 [Build: 1700761919]",
	Sign:     "oFMyO1h6nZOmA0sM9DP+6fy69t+o1drV3inNG+kaH7pZGYqgUg9r/Xu8jGaD2EqZ+Vc7JnO8Zl9Y5n3+HPNkAQ==",
}

// Windows_3_6_3_1701166057 is Windows 3.6.3, build 1701166057.
var Windows_3_6_3_1701166057 = ClientVersion{
	Platform: "Windows",
	Version:  "3.6.3 [Build: 1701166057]",
	Sign:     "ML3yE6pV0QGyhc8o7k1bgqDSj+5gZIQFMjBNhWJ6L0FtJwniBq8l1wivx3DzgVVCvyRbzfg8MsdV/rjl5sHNCw==",
}

// Linux_5_0_0_beta77_rc3_1701707182 is Linux 5.0.0-beta77-rc3, build 1701707182.
var Linux_5_0_0_beta77_rc3_1701707182 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta77-rc3 [Build: 1701707182]",
	Sign:     "bS/lxwnq0KSoNl0WggENJ/tuYm+QJF67gSqXykWGAik40iFmM1g7kYOkI5GoBsOxgWJBJB5L4dOjlAyA91BbCw==",
}

// Windows_5_0_0_beta77_1702382332 is Windows 5.0.0-beta77, build 1702382332.
var Windows_5_0_0_beta77_1702382332 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta77 [Build: 1702382332]",
	Sign:     "Ee6DzP16MUXpdKWjiSY0NGb4thN22/Ks0hwNcaMrWoaadgkM6c5477X0IbGFWVjzTWfjFTEad5noYLUPDWSgCQ==",
}

// Linux_5_0_0_beta77_1702382332 is Linux 5.0.0-beta77, build 1702382332.
var Linux_5_0_0_beta77_1702382332 = ClientVersion{
	Platform: "Linux",
	Version:  "5.0.0-beta77 [Build: 1702382332]",
	Sign:     "sJx9Ss46tDLfsJ6y73csGOXnSIRsSeUFrpHFQ2il/jjM7xWAbp8F8Cnyix/CaNwy7DfZKtgMRcPc8YP0a1r3AA==",
}

// MacOS_5_0_0_beta77_1702382332 is macOS 5.0.0-beta77, build 1702382332.
var MacOS_5_0_0_beta77_1702382332 = ClientVersion{
	Platform: "macOS",
	Version:  "5.0.0-beta77 [Build: 1702382332]",
	Sign:     "E2rqU9M9HvWnqZbki0+blgLmDWneDZZP9TW89lDDuDoQ7GaqXizzNfvr9XJBm8dJwToLfpR9/9kmLhZpHkK3Dg==",
}

// Windows_5_0_0_qa_lm_29_1719554519 is Windows 5.0.0-qa-lm-29, build 1719554519.
var Windows_5_0_0_qa_lm_29_1719554519 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-lm-29 [Build: 1719554519]",
	Sign:     "mSNqoUO2xaP31n8wrHwuAHHYrgov4ZQmq5OrgvOF0jsEQvTy11Z29j02q3nUA+k9TrXyG12CMYVUWfe8ltneBg==",
}

// Windows_5_0_0_qa_puzzle_2_1_1723116226 is Windows 5.0.0-qa-puzzle-2-1, build 1723116226.
var Windows_5_0_0_qa_puzzle_2_1_1723116226 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-puzzle-2-1 [Build: 1723116226]",
	Sign:     "7Qx8GeSIEvRNZ4D3aNbX0AO67Awj92afgNCgkJ7L0YdcaD0c1HFs0c2Ms6CArTiD8pB/Nxw7QgCsKcpBln1PCg==",
}

// Windows_5_0_0_beta78_pre_1_1724839559 is Windows 5.0.0-beta78-pre-1, build 1724839559.
var Windows_5_0_0_beta78_pre_1_1724839559 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta78-pre-1 [Build: 1724839559]",
	Sign:     "fy7cW8uGyr7lA/5eqsNztXA2nS0PbFZQgIo2HNMbNPycLWJLA8DNZGafBgsfchx9EF5piNtMsJAs9JSy1Pp8DA==",
}

// Windows_5_0_0_qa_78_18_1724924030 is Windows 5.0.0-qa-78-18, build 1724924030.
var Windows_5_0_0_qa_78_18_1724924030 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-78-18 [Build: 1724924030]",
	Sign:     "/86Ug4O5Huvf1fHooxLOqIxOIp2wyyR821wOcXkDkbXawEbsp1K7GcVqPH/cyLbfKO6x4LeCILqsrV4no3pMCg==",
}

// Windows_5_0_0_qa_78_19_1724930118 is Windows 5.0.0-qa-78-19, build 1724930118.
var Windows_5_0_0_qa_78_19_1724930118 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-78-19 [Build: 1724930118]",
	Sign:     "m2z53BpS7ocld0/TuasTKe1vXvGB6ZFR9mhdAt5I4j3QZpFlCy3NeObvQEHu+a+4Dr8yFBusdQ6vR8Jf23uyCQ==",
}

// Windows_5_0_0_beta78_pre_2_1725011227 is Windows 5.0.0-beta78-pre-2, build 1725011227.
var Windows_5_0_0_beta78_pre_2_1725011227 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta78-pre-2 [Build: 1725011227]",
	Sign:     "v6UJ+WoJ/TYQe2MqDfoXcMLPTb2L8KrN03x2WHSdsJY17yn6ofLpMtNuBLa84by+sNi1/b8htf0HdV+6TLKEDg==",
}

// Windows_5_0_0_qa_78_20_1725620142 is Windows 5.0.0-qa-78-20, build 1725620142.
var Windows_5_0_0_qa_78_20_1725620142 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-78-20 [Build: 1725620142]",
	Sign:     "hxdPF5JpyHwDb36xlKAls6wgmhGh1OvIeo4PlqVX8a9zzP0NvGVR1O2BUdo7ixFsKqrzeHoHJ7KoVxenvGpLCw==",
}

// Windows_5_0_0_qa_78_21_1726235323 is Windows 5.0.0-qa-78-21, build 1726235323.
var Windows_5_0_0_qa_78_21_1726235323 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-78-21 [Build: 1726235323]",
	Sign:     "OiQZT9J/s6kIOX6UUDEB5tu3DrKYz6S7Lay/BaXY6teJcbkIuhBr1MREgmkg8Z+yIEHpIqrV73sUqHD2vk+lAg==",
}

// Windows_5_0_0_qa_78_22_1726816276 is Windows 5.0.0-qa-78-22, build 1726816276.
var Windows_5_0_0_qa_78_22_1726816276 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-78-22 [Build: 1726816276]",
	Sign:     "dfh0I4RAn1OSy6GrlSmStLBZWutnmUEg7D4tWvzC668p3FBsm7az/CexueslYeoXKgFj871k4F/CyDCgKtCUBA==",
}

// Windows_5_0_0_qa_78_23_1727272684 is Windows 5.0.0-qa-78-23, build 1727272684.
var Windows_5_0_0_qa_78_23_1727272684 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-qa-78-23 [Build: 1727272684]",
	Sign:     "OkGqYGggz96MOy29Q7kkNi1sWbGkS6B0K//l7E8oixEdS6xdLgW6GmxwcI6DxvwBjVICg0TdO+VhGpRC9RnUCQ==",
}

// Windows_5_0_0_beta78_pre_5_1728287639 is Windows 5.0.0-beta78-pre-5, build 1728287639.
var Windows_5_0_0_beta78_pre_5_1728287639 = ClientVersion{
	Platform: "Windows",
	Version:  "5.0.0-beta78-pre-5 [Build: 1728287639]",
	Sign:     "r9IEzCKmd1M5JszuUU02xy1qFkxKAPAHa45mzxakCqibCdzdL5+T6L+OepdbB6xOKSQ+uAyAFJOd6FHX4vJ7BA==",
}

// Windows_6_0_0_beta2_1737468425 is Windows 6.0.0-beta2, build 1737468425.
var Windows_6_0_0_beta2_1737468425 = ClientVersion{
	Platform: "Windows",
	Version:  "6.0.0-beta2 [Build: 1737468425]",
	Sign:     "b5mySiqYAd4Lv5TZNflW+G5Gk8y7Woo9YnJfHRjmzhUyMdGfF1O7fSGJzmx2Hpe/PKaY2aDuKKD6lSxbLYlKCw==",
}

// Windows_3_X_X_5680278000 is Windows 3.?.?, build 5680278000.
var Windows_3_X_X_5680278000 = ClientVersion{
	Platform: "Windows",
	Version:  "3.?.? [Build: 5680278000]",
	Sign:     "DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg==",
}

// Windows_3_X_X_5680278000_DEBUG is Windows 3.?.?, build 5680278000 DEBUG.
var Windows_3_X_X_5680278000_DEBUG = ClientVersion{
	Platform: "Windows",
	Version:  "3.?.? [Build: 5680278000] DEBUG",
	Sign:     "FaA10gndI44f19ZThYJX2OSM8ESrx9/vJ2uY+rON4enzzPsPR9kiPhsUXtMcC5szzTu6F/vLCiNNEhCr70CKCQ==",
}

// Linux_3_X_X_5680278000 is Linux 3.?.?, build 5680278000.
var Linux_3_X_X_5680278000 = ClientVersion{
	Platform: "Linux",
	Version:  "3.?.? [Build: 5680278000]",
	Sign:     "Hjd+N58Gv3ENhoKmGYy2bNRBsNNgm5kpiaQWxOj5HN2DXttG6REjymSwJtpJ8muC2gSwRuZi0R+8Laan5ts5CQ==",
}

// OSX_3_X_X_5680278000 is OS X 3.?.?, build 5680278000.
var OSX_3_X_X_5680278000 = ClientVersion{
	Platform: "OS X",
	Version:  "3.?.? [Build: 5680278000]",
	Sign:     "SttEnjoWE8jqIM6BOHSfiZP9DGjW0EP/ajU4bdKqgGMV4aYq/kzwVA9gxbmdIzV4lbaokvXBqrRjfBHrTVh8Cg==",
}

// Android_3_X_X_5680278000 is Android 3.?.?, build 5680278000.
var Android_3_X_X_5680278000 = ClientVersion{
	Platform: "Android",
	Version:  "3.?.? [Build: 5680278000]",
	Sign:     "AWb948BY32Z7bpIyoAlQguSmxOGcmjESPceQe1DpW5IZ4+AW1KfTk2VUIYNfUPsxReDJMCtlhVKslzhR2lf0AA==",
}

// IOS_3_X_X_5680278000 is iOS 3.?.?, build 5680278000.
var IOS_3_X_X_5680278000 = ClientVersion{
	Platform: "iOS",
	Version:  "3.?.? [Build: 5680278000]",
	Sign:     "XrAf+Buq6Eb0ehEW/niFp06YX+nGGOS0Ke4MoUBzn+cX9q6G5C0A/d5XtgcNMe8r9jJgV/adIYVpsGS3pVlSAA==",
}
