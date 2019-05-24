/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SimpleAESEncryptionLib;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Interfaccia per le classi di cifratura e decifratura
 *
 * @author utente
 */
public abstract class CryptographyBaseClass {
    /**
     * Ritorna il numero massimo permesso per la chiave AES. 
     * Se è impostato il corretto file crypto.policy il valore è 
     * @return il massimo numero di bit per la chiave
     */
    public static int getMaxAllowedKeyLength() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptographyBaseClass.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return -1;
    }

    /**
     * Codifica una stringa di testo utilizzando la password già impostata per
     * la classe
     *
     * @param plaintext Stringa da crittografare
     * @return Array di byte che rappresentano la stringa crittografata
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    public abstract byte[] encode(String plaintext) throws GeneralSecurityException, UnsupportedEncodingException;

    /**
     * Decodifica una stringa di testo rappresentata come array di byte
     * utilizzando la password già impostata per la classe
     *
     * @param encoded Array di byte che rappresentano i dati crittografati
     * @return Stringa decifrata
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    public abstract String decode(byte[] encoded) throws GeneralSecurityException, UnsupportedEncodingException;

    /**
     * Ritorna la chiave segreta generata a partire dalla password impostata
     * nella classe
     *
     * @return Chiave segreta generata dalla password impostata nella classe
     */
    public abstract SecretKeySpec getSecretKey();

    /**
     * Reimposta la chiave segreta
     *
     * @param secretKeySpec
     */
    public abstract void setSecretKey(SecretKeySpec secretKeySpec);

    /**
     * Ritorna il salt
     *
     * @return
     */
    protected abstract byte[] getSalt();

    /**
     * Imposta il salt
     *
     * @param salt
     */
    protected abstract void setSalt(byte[] salt);

    /**
     * Imposta un salt casuale
     */
    protected abstract void setRandomSalt();

    /**
     * Risprna il vettore di inizializzazione iniziale
     *
     * @return
     */
    protected abstract byte[] getIVVector();

    /**
     * Imposta il vettore di inizializzazione
     *
     * @param iv
     * @throws java.security.GeneralSecurityException
     */
    protected abstract void setIVVector(byte[] iv) throws GeneralSecurityException;

    /**
     * Codifica un file scrivendolo su un altro in uscita
     *
     * @param fileClearFileInputStream File in chiaro che verrà crittografato
     * @param fileEncodedOutputStream File dove verrà scritto il contenuto
     * crittografato
     *
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     * @throws GeneralSecurityException
     */
    public abstract void encodeFile(FileInputStream fileClearFileInputStream, FileOutputStream fileEncodedOutputStream) throws
            IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException;

    /**
     *
     * @param fileEncodedFileInputStream File crittorafato che verrà decifrato
     * @param fileClearOutputStream File dove verrà scritto il contenuto in
     * chiaro
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     * @throws GeneralSecurityException
     */
    public abstract void decodeFile(FileInputStream fileEncodedFileInputStream, FileOutputStream fileClearOutputStream) throws
            IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException;

    /**
     * Imposta la password della classe. La vecchia password eventualmente
     * impostata viene sovrascritta Viene generato un salt casuale
     *
     * @param pass Password rappresentata come array di char
     * @throws GeneralSecurityException
     */
    protected abstract void setPass(char[] pass) throws GeneralSecurityException;

    /**
     * Imposta la password con il salt specificato
     *
     * @param pass
     * @param salt
     * @throws GeneralSecurityException
     */
    public abstract void setPass(char[] pass, byte[] salt) throws GeneralSecurityException;

    /**
     * Inizializza la chiave segreta con la password, il salt e l'initVector
     *
     * @param pass
     * @param salt
     * @param iv
     * @throws GeneralSecurityException
     */
    public abstract void initSecretParameters(char[] pass, byte[] salt, byte[] iv) throws GeneralSecurityException;

    /**
     * Crea la chiave per cifrare e decifrare usando i parametri password, salt
     * e IV impostati per l'oggetto
     *
     * @throws GeneralSecurityException
     */
    public abstract void createKey() throws GeneralSecurityException;

    /**
     * Crea la chiave per cifrare e decifrare
     *
     * @param pass
     * @param salt
     * @throws GeneralSecurityException
     */
    public abstract void createKey(char[] pass, byte[] salt) throws GeneralSecurityException;

    /**
     * Crea l'oggetto Cipher per le operazioni di cifratura e decifratura
     *
     * @param modeIsEncrypt True per crittografare False per decifrare
     * @return Oggetto Cipher opportunamente configurato
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     * @throws GeneralSecurityException
     */
    public abstract Cipher createCipher(boolean modeIsEncrypt) throws
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException;
}
