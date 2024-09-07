# ABL-RC4
### ABL RC4 cipher

rc4.cls is a static class object for OpenEdge ABL.


Example:
```
DEFINE VARIABLE encyptedCipher AS CHARACTER NO-UNDO.
DEFINE VARIABLE privateKey     AS CHARACTER NO-UNDO.
DEFINE VARIABLE data           AS CHARACTER NO-UNDO.

ASSIGN
    privateKey = "not-so-random-key".
    data  = "RC4 (also known as ARC4) is a stream cipher used in popular protocols such as SSL and WEP.~r~nWhile remarkable for its simplicity and speed, multiple vulnerabilities have rendered it insecure.".

encyptedCipher = rc4:Cipher(data, privateKey).

MESSAGE "Hex encoded encypted string" STRING(rc4:StringToHex(INPUT encyptedCipher, INPUT TRUE))
    VIEW-AS ALERT-BOX INFO.

Assign
    data = ""
    data = rc4:Cipher (encyptedCipher, privateKey).

MESSAGE "Plain Text decoded string" data
    VIEW-AS ALERT-BOX INFO.
