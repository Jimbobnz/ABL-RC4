/* RC4 Encryption/Decryption Function in Progress ABL */

FUNCTION bitXOR RETURNS INTEGER (INPUT X AS INTEGER, INPUT Y AS INTEGER):
    DEFINE VARIABLE b1 AS INTEGER NO-UNDO.
    DEFINE VARIABLE b2 AS INTEGER NO-UNDO.
    DEFINE VARIABLE n  AS INTEGER NO-UNDO.
    DEFINE VARIABLE Z  AS INTEGER NO-UNDO.

    DO n = 1 TO 32:
        ASSIGN
            b1 = GET-BITS(X, n, 1)
            b2 = GET-BITS(Y, n, 1)
            .
        IF b1 + b2 = 1 THEN PUT-BITS(Z, n, 1) = 1.
    END.

    RETURN Z.
END FUNCTION.

FUNCTION bitAnd RETURNS INTEGER ( INPUT X AS INTEGER, INPUT Y AS INTEGER):

    DEFINE VARIABLE b AS INTEGER NO-UNDO.
    DEFINE VARIABLE n AS INTEGER NO-UNDO.
    DEFINE VARIABLE Z AS INTEGER NO-UNDO.

    DO n = 1 TO 32:
        IF GET-BITS(X, n, 1) = 1 AND get-bits(Y, n, 1) = 1 THEN
            b = 1.

        PUT-BITS(Z, n, 1) = b.
        b = 0.
    END.

    RETURN Z.
END FUNCTION.

FUNCTION RC4 RETURNS MEMPTR
    (INPUT pwd AS MEMPTR, INPUT data AS MEMPTR):

    DEFINE VARIABLE a          AS INTEGER NO-UNDO.
    DEFINE VARIABLE i          AS INTEGER NO-UNDO.
    DEFINE VARIABLE j          AS INTEGER NO-UNDO.
    DEFINE VARIABLE k          AS INTEGER NO-UNDO.
    DEFINE VARIABLE tmp        AS INTEGER NO-UNDO.
    DEFINE VARIABLE key        AS INTEGER EXTENT 256 NO-UNDO.
    DEFINE VARIABLE box        AS INTEGER EXTENT 256 NO-UNDO.
    DEFINE VARIABLE dataLength AS INTEGER NO-UNDO.
    DEFINE VARIABLE pwdLength  AS INTEGER NO-UNDO.
    DEFINE VARIABLE cipher     AS MEMPTR  NO-UNDO.
    DEFINE VARIABLE cPtr       AS INTEGER NO-UNDO. /* Pointer for MEMPTR manipulation */
    
    
    /* Initialize lengths */
    ASSIGN
        dataLength = GET-SIZE(data)
        pwdLength  = GET-SIZE(pwd).

    /* Allocate memory for the cipher */
    SET-SIZE(cipher) = 0.
    SET-SIZE(cipher) = dataLength.
    cPtr = 1.

    /* Key-scheduling algorithm (KSA) */
    DO i = 1 TO 256:
        ASSIGN
            key[i] = GET-BYTE(pwd, (i - 1) MODULO pwdLength + 1)
            box[i] = i - 1.
    END.

    j = 1.
    DO i = 1 TO 256:
        j = (j + box[i] + key[i]) MODULO 256 + 1.
        /* Swap */
        ASSIGN
            tmp    = box[i]
            box[i] = box[j]
            box[j] = tmp.
    END.

    /* Pseudo-random generation algorithm (PRGA) */
    a = 1.
    j = 1.
    DO i = 1 TO dataLength:
        ASSIGN
            a = a MODULO 256 + 1
            j = (j + box[a]) MODULO 256 + 1.
        
        /* Swap */
        ASSIGN
            tmp    = box[a]
            box[a] = box[j]
            box[j] = tmp.

        ASSIGN    
            k   = box[(box[a] + box[j]) MODULO 256 + 1]
            tmp = bitXOR(GET-BYTE(data, i),  k).  // XOR the data with the generated key stream and store in cipher
        
        PUT-BYTE(cipher, cPtr) = bitAnd(tmp, 255).
        
        cPtr = cPtr + 1.
    END.

    RETURN cipher.
    
    FINALLY:
        SET-SIZE(cipher) = 0.
    END.

END FUNCTION.

/* Test the RC4 function */
DEFINE VARIABLE pwd                  AS MEMPTR    NO-UNDO.
DEFINE VARIABLE data                 AS MEMPTR    NO-UNDO.
DEFINE VARIABLE encrypted            AS MEMPTR    NO-UNDO.
DEFINE VARIABLE decrypted            AS MEMPTR    NO-UNDO.
DEFINE VARIABLE tempString           AS CHARACTER NO-UNDO.
DEFINE VARIABLE passwordString       AS CHARACTER NO-UNDO.
DEFINE VARIABLE dataEncryptionString AS CHARACTER NO-UNDO.

/* Alway zero out your memptrs */
SET-SIZE(pwd) = 0.
SET-SIZE(data) = 0.
SET-SIZE(encrypted) = 0.
SET-SIZE(decrypted) = 0.

ASSIGN
    passwordString       = "This is the private key!"
    dataEncryptionString = "RC4 (also known as Rivest Cipher 4) is a form of stream cipher. It encrypts messages one byte at a time via an algorithm.~r~n~r~nPlenty of stream ciphers exist, but RC4 is among the most popular. It's simple to apply, and it works quickly, even on very large pieces of data. If you've ever used an application like TSL (transport layer security) or SSL (secure socket layer), you've probably encountered RC4 encryption.~r~n~r~nBut you may not know how it works.~r~n~r~nWe'll take a high-level approach and explain what the Rivest Cipher is in terms anyone can understand. We'll also explain why it's helpful, and we'll point out a few known limitations. EOL". 

SET-SIZE(pwd) = LENGTH(passwordString).
SET-SIZE(data) = LENGTH(dataEncryptionString).

PUT-STRING(pwd, 1, LENGTH(passwordString)) = passwordString.
PUT-STRING(data, 1, LENGTH(dataEncryptionString)) = dataEncryptionString.

/* Encrypt the data */
encrypted = RC4(pwd, data).

tempString  = GET-STRING(encrypted, 1) .

MESSAGE "Encrypted (HEX): " STRING(HEX-ENCODE(encrypted)) SKIP(1)
    "Encrypted (TXT): " tempString 
    VIEW-AS ALERT-BOX INFORMATION TITLE "ABL ARC4 Encryption (Encrypted)".

/* Decrypt the data (using the same RC4 function) */
ASSIGN
    decrypted = RC4(pwd, encrypted).

tempString  = GET-STRING(decrypted, 1).

MESSAGE "Decrypted: " tempString  VIEW-AS ALERT-BOX INFORMATION TITLE "ABL ARC4 Encryption (Decrypted)".

/* Clean up */
FINALLY:
    SET-SIZE(pwd) = 0.
    SET-SIZE(data) = 0.
    SET-SIZE(encrypted) = 0.
    SET-SIZE(decrypted) = 0.
END.
