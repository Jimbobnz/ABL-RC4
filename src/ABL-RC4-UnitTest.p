
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



/* **********************  Internal Procedures  *********************** */


PROCEDURE StreamProgress:
    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/

    DEFINE INPUT PARAMETER streamPos AS DECIMAL NO-UNDO. 
    DEFINE INPUT PARAMETER streamSize AS DECIMAL NO-UNDO.

    MESSAGE ROUND((streamPos / streamSize) * 100, 2) '%'.
    
    RETURN.
END PROCEDURE.  

DEFINE VARIABLE encyptedCipher AS CHARACTER NO-UNDO.
DEFINE VARIABLE privateKey     AS CHARACTER NO-UNDO.
DEFINE VARIABLE data           AS CHARACTER NO-UNDO.
    
ASSIGN
    privateKey = "not-so-random-key".
    data  = "RC4 (also known as ARC4) is a stream cipher used in popular protocols such as SSL and WEP. While remarkable for its simplicity and speed, multiple vulnerabilities have rendered it insecure.".

encyptedCipher = rc4:Cipher(data, privateKey).

MESSAGE "Hex encoded encypted string:" skip 
        STRING(rc4:StringToHex(INPUT encyptedCipher, INPUT TRUE))
    VIEW-AS ALERT-BOX INFO.
    
/** Subscript the Stream Progress event.**/    
rc4:StreamProgress:Subscribe( THIS-PROCEDURE, "StreamProgress").    

ASSIGN
    data = ""
    data = rc4:Cipher (encyptedCipher, privateKey).

MESSAGE "Plain Text decoded string" data
    VIEW-AS ALERT-BOX INFO.

/** Un-Subscript the Stream Progress event.**/
rc4:StreamProgress:Unsubscribe( THIS-PROCEDURE, "StreamProgress" ).
