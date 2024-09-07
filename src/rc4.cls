 
/*------------------------------------------------------------------------
   File        : rc4.cls
   Purpose     : Class Object to encrypt/decrept data
   Syntax      : 
   Description : 
   Author(s)   : James Bowen
   Created     : Wed Aug 28 09:14:34 NZST 2024
   Notes       : RC4 (also known as ARC4) is a stream cipher used in 
                 popular protocols such as SSL and WEP. While remarkable 
                 for its simplicity and speed, multiple vulnerabilities 
                 have rendered it insecure.
 ----------------------------------------------------------------------*/

USING Progress.Lang.*.

BLOCK-LEVEL ON ERROR UNDO, THROW.

CLASS rc4:
    
    DEFINE STATIC TEMP-TABLE ttPrivateKey NO-UNDO
        FIELD indexPos  AS INTEGER
        FIELD valueByte AS INTEGER
        INDEX idxIndexPos IS PRIMARY UNIQUE
        indexPos.
        .

    DEFINE STATIC TEMP-TABLE ttS NO-UNDO
        FIELD indexPos  AS INTEGER
        FIELD valueByte AS INTEGER
        INDEX idxIndexPos IS PRIMARY UNIQUE
        indexPos. 

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
    
    METHOD PUBLIC STATIC CHARACTER Cipher(INPUT data AS CHARACTER, INPUT privateKey AS LONGCHAR):
        
        DEFINE VARIABLE result   AS CHARACTER NO-UNDO.
        DEFINE VARIABLE resultlc AS LONGCHAR  NO-UNDO.
        DEFINE VARIABLE datalc   AS LONGCHAR  NO-UNDO.
        
        ASSIGN
            datalc = data.
            
        resultlc = Cipher(INPUT datalc, INPUT privateKey ).
        
        RETURN STRING(resultlc).
        
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
    
    METHOD PUBLIC STATIC MEMPTR Cipher(INPUT data AS MEMPTR, INPUT privateKey AS LONGCHAR  ):
        
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
        
        
        IF GET-SIZE(privateKey) < 1 OR get-size(privateKey) > 256 THEN
            RETURN ERROR "Invalid password length".
        
        /* Initialise */
        KSA(INPUT privateKey).
        
        RETURN PRGA(INPUT data ).
        
        FINALLY:
            
        
            set-size(data) = 0.
            set-size(privateKey) = 0.
            
        END.

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose: EncryptingFiles
     Notes:
    ------------------------------------------------------------------------------*/

    METHOD PUBLIC STATIC LOGICAL CipherFile( INPUT dataSourceFilename AS CHARACTER, 
                                             INPUT dataTargetFilename AS CHARACTER, 
                                             INPUT privateKey         AS CHARACTER):
        
        DEFINE VARIABLE result     AS LOGICAL NO-UNDO.
        DEFINE VARIABLE dataSource AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE dataTarget AS MEMPTR  NO-UNDO.

        COPY-LOB FROM FILE dataSourceFilename TO dataSource.
        
        dataTarget = Cipher(INPUT dataSource, INPUT privateKey).
        
        COPY-LOB FROM OBJECT dataTarget TO FILE dataTargetFilename.
        
        RETURN (IF SEARCH(dataTargetFilename) NE ? THEN TRUE ELSE FALSE).
        
    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose:  privateKey Scheduling Algorithm (KSA) 
     Notes:
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC VOID KSA( INPUT  privateKey AS MEMPTR ):
        
        DEFINE VARIABLE privateKeyLength AS INTEGER NO-UNDO.
        DEFINE VARIABLE i                AS INTEGER NO-UNDO.
        DEFINE VARIABLE j                AS INTEGER NO-UNDO.
    
        ASSIGN
            privateKeyLength = GET-SIZE(privateKey).
    
        /* Initialize the S temp-table array */
        EMPTY TEMP-TABLE ttS.
        EMPTY TEMP-TABLE ttPrivateKey.
    
        DO i = 0 TO 255:
            CREATE ttS.
            ASSIGN
                ttS.indexPos  = i
                ttS.valueByte = i.
            RELEASE ttS.
        END.
    
        DO i = 1 TO privateKeyLength :
            CREATE ttPrivateKey.
        
            ASSIGN
                ttPrivateKey.indexPos  = i - 1
                ttPrivateKey.valueByte = GET-BYTE(privateKey, i).
            RELEASE ttPrivateKey.    
        END.
    
        ASSIGN
            j = 0.

        DO i = 0 TO 255:
            j = (j + StreamByteValue(i) + KeyByteValue( i MOD privateKeyLength )) MOD 256.
            Swap(i, j).
        END.
        
        RETURN .

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose: Psudo Random Generation Algorithm
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC MEMPTR PRGA( INPUT inputData AS MEMPTR ):
        
    
        DEFINE VARIABLE outputData           AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE byteToEncrypt        AS INTEGER NO-UNDO.
    
        /* Encrypt/Decrypt */
        
        DEFINE VARIABLE inputDataLength      AS INTEGER NO-UNDO.
        DEFINE VARIABLE privateKeyStreamByte AS INTEGER NO-UNDO.
        DEFINE VARIABLE i                    AS INTEGER NO-UNDO.
        DEFINE VARIABLE x                    AS INTEGER NO-UNDO.
        DEFINE VARIABLE y                    AS INTEGER NO-UNDO.

        ASSIGN    
            inputDataLength = GET-SIZE(inputData).
    
        set-size(outputData) = 0.
        set-size(outputData) = inputDataLength.
        
        ASSIGN
            x = 0
            y = 0.

        DO i = 1 TO inputDataLength:
            
            IF ETIME MOD 500 EQ 0 THEN 
                PROCESS EVENTS.
            
            ASSIGN
                x = (x + 1) MOD 256
                y = (y + StreamByteValue(x)) MOD 256.

            Swap(x, y).
            
            ASSIGN
                privateKeyStreamByte = StreamByteValue( (StreamByteValue(x) + StreamByteValue(y)) MOD 256)
                byteToEncrypt        = GET-BYTE(inputData, i).
                
            put-byte(outputData,i) = bitXOR( byteToEncrypt , privateKeyStreamByte ).
        
        END.
    
        RETURN outputData.

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose: Helper Method to convert a string into HEX notation.
    ------------------------------------------------------------------------------*/
    
    METHOD PUBLIC STATIC LONGCHAR StringToHex( INPUT stringData AS CHARACTER ):
        
        RETURN StringToHex( INPUT stringData , INPUT FALSE ).
        
    END METHOD.    

    METHOD PUBLIC STATIC LONGCHAR StringToHex( INPUT stringData AS CHARACTER, INPUT formatted AS LOGICAL ):
        
        DEFINE VARIABLE result           AS LONGCHAR NO-UNDO.
        DEFINE VARIABLE memprtData       AS MEMPTR   NO-UNDO.
        DEFINE VARIABLE stringDataLength AS INTEGER  NO-UNDO.
        DEFINE VARIABLE i                AS INTEGER  NO-UNDO.
        
        stringDataLength =  LENGTH(stringData,"RAW").
        
        IF stringDataLength GT 0 THEN
        DO:
        
            set-size(memprtData) = 0.
            set-size(memprtData) = stringDataLength.
            
            put-string(memprtData,1,stringDataLength) = stringData.
            
            result = HEX-ENCODE(memprtData).
        
        END.
        
        IF formatted THEN
        DO:
            
            i = 1.
            DO WHILE i < length(result):
                SUBSTRING(result, i, 0, "CHARACTER" ) = " ".
                i = i + 3.  // move along to the 3rd character
            END.
            
            result = TRIM(result).
            
        END.
            
        RETURN result.
        
        FINALLY:
            set-size(memprtData) = 0.
        END.

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC VOID Swap(INPUT i AS INTEGER, INPUT j AS INTEGER  ):
        
        DEFINE VARIABLE temp AS INTEGER NO-UNDO.
    
        DEFINE BUFFER buffer1 FOR TEMP-TABLE ttS.
        DEFINE BUFFER buffer2 FOR TEMP-TABLE ttS.
    
        FIND buffer1 WHERE buffer1.indexPos EQ i.
        FIND buffer2 WHERE buffer2.indexPos EQ j.
    
        ASSIGN
            temp              = buffer1.valueByte
            buffer1.valueByte = buffer2.valueByte
            buffer2.valueByte = temp.
        
        RETURN.

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC INTEGER KeyByteValue( INPUT pIndexPos AS INTEGER ):
            
        DEFINE BUFFER ttPrivateKeyBuffer FOR TEMP-TABLE ttPrivateKey.
    
        FIND ttPrivateKeyBuffer WHERE ttPrivateKeyBuffer.indexPos EQ pIndexPos.
    
        RETURN ttPrivateKeyBuffer.valueByte.

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose:
     Notes:
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC INTEGER StreamByteValue( INPUT pIndexPos AS INTEGER ):
        
        DEFINE BUFFER ttBuffer FOR TEMP-TABLE ttS.
    
        FIND ttBuffer WHERE ttBuffer.indexPos EQ pIndexPos.
    
        RETURN ttBuffer.valueByte.

    END METHOD.

END CLASS.