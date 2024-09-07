
/*------------------------------------------------------------------------
    File        : ABL-RC4-UnitTest.p
    Purpose     : 

    Syntax      :

    Description : 

    Author(s)   : James Bowen
    Created     : Sat Sep 07 19:54:34 NZST 2024
    Notes       :
  ----------------------------------------------------------------------*/

/* ***************************  Definitions  ************************** */

BLOCK-LEVEL ON ERROR UNDO, THROW.

/* ********************  Preprocessor Definitions  ******************** */


/* ***************************  Main Block  *************************** */

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

ETIME(TRUE).
MESSAGE "Encoding ".
rc4:CipherFile(INPUT "planets-org.jpg", //Input file to be encrypted/decrypted 
               INPUT "planets-org.jpg.rc4", //Output file to be encrypted/decrypted 
               INPUT privateKey) .
MESSAGE "Done"  ETIME "ms".


ETIME(TRUE).               
MESSAGE "Decodeing" . 
rc4:CipherFile(INPUT "planets-org.jpg.rc4", //Input file to be encrypted/decrypted  
               INPUT "planets-decoded.jpg", //Output file to be encrypted/decrypted
               INPUT privateKey) .
MESSAGE "Done"  ETIME "ms".
