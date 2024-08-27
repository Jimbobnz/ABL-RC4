 
/*------------------------------------------------------------------------
   File        : rc4
   Purpose     : 
   Syntax      : 
   Description : 
   Author(s)   : James Bowen
   Created     : Wed Aug 28 09:14:34 NZST 2024
   Notes       : 
 ----------------------------------------------------------------------*/

USING Progress.Lang.*.

BLOCK-LEVEL ON ERROR UNDO, THROW.

CLASS rc4: 

    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC INTEGER bitAnd( INPUT X AS INTEGER, INPUT Y AS INTEGER):

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

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC INTEGER bitXOR(INPUT X AS INTEGER, INPUT Y AS INTEGER):
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

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/
    
    METHOD PUBLIC STATIC CHARACTER Cipher(INPUT data AS CHARACTER, INPUT privateKey AS CHARACTER  ):
        
        DEFINE VARIABLE result       AS CHARACTER NO-UNDO.
        DEFINE VARIABLE resultlc     AS LONGCHAR  NO-UNDO.
        
        DEFINE VARIABLE datalc       AS LONGCHAR  NO-UNDO.
        DEFINE VARIABLE privateKeylc AS LONGCHAR  NO-UNDO.
        
        ASSIGN
            datalc       = data
            privateKeylc = privateKey.
            
        
        resultlc = Cipher(INPUT datalc, INPUT privateKeylc ).
        
        RETURN STRING( resultlc ).
        
    END METHOD.
    
    METHOD PUBLIC STATIC CHARACTER Cipher(INPUT data AS CHARACTER, INPUT privateKey AS longchar):
        
        DEFINE VARIABLE result   AS CHARACTER NO-UNDO.
        DEFINE VARIABLE resultlc AS LONGCHAR  NO-UNDO.
        DEFINE VARIABLE datalc   AS LONGCHAR  NO-UNDO.
        
        ASSIGN
            datalc = data.
            
        resultlc = Cipher(INPUT datalc, INPUT privateKey ).
        
        RETURN string(resultlc).
        
    END METHOD.    
    
    METHOD PUBLIC STATIC LONGCHAR Cipher(INPUT data AS LONGCHAR, INPUT privateKey AS CHARACTER):
        
        DEFINE VARIABLE result       AS CHARACTER NO-UNDO.
        DEFINE VARIABLE resultlc     AS LONGCHAR  NO-UNDO.
        
        
        DEFINE VARIABLE privateKeylc AS LONGCHAR  NO-UNDO.
        
        ASSIGN
            privateKeylc = privateKey
            resultlc     = Cipher(INPUT data, INPUT privateKeylc ).
        
        RETURN STRING( resultlc ).
        
    END METHOD.    
    
    METHOD PUBLIC STATIC MEMPTR Cipher(INPUT data AS MEMPTR, INPUT privateKey AS longchar  ):
        
        DEFINE VARIABLE privateKeyMemptr AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE privateKeyLength AS INTEGER NO-UNDO.
        
        ASSIGN
            privateKeyLength = LENGTH(privateKey).
            
        set-size(privateKeyMemptr) = 0.
        set-size(privateKeyMemptr) = privateKeyLength.
        put-string(privateKeyMemptr, 1, privateKeyLength) = privateKey.
        
        RETURN Cipher(INPUT data, INPUT privateKeyMemptr ).
        
        FINALLY:
            set-size(privateKeyMemptr) = 0.
            
        END.
        
    END METHOD.       
    
    METHOD PUBLIC STATIC MEMPTR Cipher(INPUT data AS MEMPTR, INPUT privateKey AS CHARACTER  ):
        
        DEFINE VARIABLE privateKeyMemptr AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE privateKeyLength AS INTEGER NO-UNDO.
        
        ASSIGN
            privateKeyLength = LENGTH(privateKey).
            
        set-size(privateKeyMemptr) = 0.
        set-size(privateKeyMemptr) = privateKeyLength.
        put-string(privateKeyMemptr, 1, privateKeyLength) = privateKey.
        
        RETURN Cipher(INPUT data, INPUT privateKeyMemptr).
        
        FINALLY:
            set-size(privateKeyMemptr) = 0.
            
        END.
        
    END METHOD.    
    
    METHOD PUBLIC STATIC LONGCHAR Cipher(INPUT data AS LONGCHAR, INPUT privateKey AS LONGCHAR  ):
        
        DEFINE VARIABLE dataMemptr       AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE privateKeyMemptr AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE cipherMemptr     AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE dataLength       AS INTEGER NO-UNDO.
        DEFINE VARIABLE privateKeyLength AS INTEGER NO-UNDO.
        
        ASSIGN
            dataLength       = LENGTH(data)
            privateKeyLength = LENGTH(privateKey).
        
        IF dataLength = 0 OR privateKeyLength EQ 0 THEN  
            RETURN ERROR "Data or private Key is zero length". 
            
        set-size(dataMemptr) = 0.
        set-size(dataMemptr) = dataLength.
        set-size(privateKeyMemptr) = 0.
        set-size(privateKeyMemptr) = privateKeyLength.
        set-size(cipherMemptr) = 0.     
        
        put-string(dataMemptr, 1, dataLength) = data.
        put-string(privateKeyMemptr, 1, privateKeyLength) = privateKey.
        
        cipherMemptr = Cipher(INPUT dataMemptr, INPUT privateKeyMemptr).
        
        RETURN GET-STRING(cipherMemptr, 1, dataLength).

        FINALLY:
            
            set-size(cipherMemptr) = 0.
            set-size(dataMemptr) = 0.
            set-size(privateKeyMemptr) = 0.
            
        END.
        
    END METHOD.    
    

    
    METHOD PUBLIC STATIC MEMPTR Cipher(INPUT data AS MEMPTR, INPUT privateKey AS MEMPTR  ):
        
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
            pwdLength  = GET-SIZE(privateKey).

        /* Allocate memory for the cipher */
        SET-SIZE(cipher) = 0.
        SET-SIZE(cipher) = dataLength.
        cPtr = 1.

        /* Key-scheduling algorithm (KSA) */
        DO i = 1 TO 256:
            ASSIGN
                key[i] = GET-BYTE(privateKey, (i - 1) MODULO pwdLength + 1)
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
            
            set-size(cipher) = 0.
            set-size(data) = 0.
            set-size(privateKey) = 0.
            
        END.

    END METHOD.

/*------------------------------------------------------------------------------
 Purpose:
 Notes:
------------------------------------------------------------------------------*/
    
    

END CLASS.