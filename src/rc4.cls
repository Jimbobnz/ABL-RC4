 
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

    DEFINE PUBLIC STATIC EVENT StreamProgress SIGNATURE VOID (INPUT streamPos AS DECIMAL, INPUT streamSize AS DECIMAL).

    /*------------------------------------------------------------------------------
     Purpose: bitXOR method because OpenEdge ABL does not have it's own bitwise opertor
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
     Purpose: Converts a character into a memptr. 
     ------------------------------------------------------------------------------*/
    
    METHOD PRIVATE STATIC MEMPTR CharToMemptr( INPUT charValue AS CHARACTER ):
        
        DEFINE VARIABLE longCharValue AS LONGCHAR NO-UNDO.
        
        ASSIGN
            longCharValue = CharValue.
        
        RETURN CharToMemptr(INPUT longCharValue).

    END METHOD.
    
    /*------------------------------------------------------------------------------
     Purpose: Converts a longchar into a memptr. 
    ------------------------------------------------------------------------------*/

    METHOD PRIVATE STATIC MEMPTR CharToMemptr( INPUT longcharValue AS LONGCHAR ):
        
        DEFINE VARIABLE tempMemptr          AS MEMPTR  NO-UNDO.
        DEFINE VARIABLE longcharValueLength AS INTEGER NO-UNDO.
        
        longcharValueLength = LENGTH(longcharValue, "RAW").
        
        set-size(tempMemptr) = 0. 
        set-size(tempMemptr) = longcharValueLength.
        put-string(tempMemptr, 1, longcharValueLength) = longcharValue.
        
        RETURN tempMemptr.
        
        FINALLY:
            set-size(tempMemptr) = 0.
        END. 

    END METHOD.
    
    /*------------------------------------------------------------------------------
     Purpose: Encrypt/Decrypt character 
    ------------------------------------------------------------------------------*/

    METHOD PUBLIC STATIC CHARACTER Cipher(INPUT data AS CHARACTER, INPUT privateKey AS CHARACTER  ):
        
        DEFINE VARIABLE resultlc         AS LONGCHAR NO-UNDO.
        DEFINE VARIABLE cipherMemptr     AS MEMPTR   NO-UNDO.
        DEFINE VARIABLE inCharacertLimit AS INTEGER  NO-UNDO INITIAL 0X8000. //32K character limit. 
        
        ASSIGN  
            inCharacertLimit = MINIMUM(inCharacertLimit, LENGTH(data,"RAW") ).
        
        cipherMemptr = Cipher(INPUT CharToMemptr(INPUT data), INPUT  CharToMemptr(INPUT privateKey)).
        
        //** Return back the first 32K characters or less **/
        RETURN GET-STRING(cipherMemptr, 1, inCharacertLimit).
        
        FINALLY:
            set-size(cipherMemptr) = 0.
        END.
        
    END METHOD.
    
    METHOD PUBLIC STATIC LONGCHAR Cipher(INPUT data AS LONGCHAR, INPUT privateKey AS CHARACTER):
        
        DEFINE VARIABLE resultlc     AS LONGCHAR NO-UNDO.
        DEFINE VARIABLE cipherMemptr AS MEMPTR   NO-UNDO.
        
        cipherMemptr = Cipher(INPUT CharToMemptr(INPUT data), INPUT  CharToMemptr(INPUT privateKey)).
        
        COPY-LOB FROM OBJECT cipherMemptr TO OBJECT resultlc.
        
        RETURN resultlc .
        
        FINALLY:
            set-size(cipherMemptr) = 0.
        END.
        
    END METHOD.    
    
    METHOD PUBLIC STATIC MEMPTR Cipher(INPUT data AS MEMPTR, INPUT privateKey AS CHARACTER  ):
        
        RETURN Cipher(INPUT data, INPUT CharToMemptr(INPUT privateKey)).
        
    END METHOD.    
    
    METHOD PUBLIC STATIC MEMPTR Cipher(INPUT data AS MEMPTR, INPUT privateKey AS MEMPTR  ):
        
        IF GET-SIZE(privateKey) LT 1 OR 
            get-size(privateKey) GT 0x100 THEN
            RETURN ERROR "Invalid password length".
        
        /* Initialise */
        KSA(INPUT privateKey).
        
        RETURN PRGA(INPUT data ).
        
        FINALLY:
            set-size(data)       = 0.
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
        
        finally:
            set-size(dataSource) = 0.
            set-size(dataTarget) = 0.
                
        end.
        
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
    
        DO i = 0 TO 0xFF:
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

        DO i = 0 TO 0xFF:
            j = (j + StreamByteValue(i) + KeyByteValue( i MOD privateKeyLength )) MOD 0x100.
            Swap(i, j).
        END.
        
        RETURN.

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
            
            /** Publis Stream Progress every 2 seconds.**/
            IF ETIME MOD 2000 EQ 0 THEN
            DO: 
                StreamProgress:Publish(INPUT i, INPUT inputDataLength).
                PROCESS EVENTS.
            END.
            
            ASSIGN
                x = (x + 1) MOD 0x100
                y = (y + StreamByteValue(x)) MOD 0x100.

            Swap(x, y).
            
            ASSIGN
                privateKeyStreamByte = StreamByteValue( (StreamByteValue(x) + StreamByteValue(y)) MOD 0x100)
                byteToEncrypt        = GET-BYTE(inputData, i).
                
            put-byte(outputData,i) = bitXOR( byteToEncrypt , privateKeyStreamByte ).
        END.
        /** 100% complete **/
        StreamProgress:Publish(INPUT inputDataLength, INPUT inputDataLength).
        
    
        RETURN outputData.

    END METHOD.

    /*------------------------------------------------------------------------------
     Purpose: Helper method to convert a string into HEX notation.
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
        
        /** Format the hex output to include a SPACE after every 2 character.**/
        IF formatted THEN
        DO:
            
            i = 1.
            DO WHILE i < LENGTH(result):
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
        
        FINALLY:
            RELEASE buffer1.
            RELEASE buffer2.
        END.

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