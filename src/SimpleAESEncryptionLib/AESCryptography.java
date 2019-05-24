/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 *
 * Classe basata quasi completamente sulla risposta di "dit" alla domanda:
 * http://codereview.stackexchange.com/questions/85396/encrypting-a-string-using-aes-cbc-pkcs5padding
 *
 */

package SimpleAESEncryptionLib;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author utente
 *
 * Classe per codificare e decodificare con l'algoritmo AES. I metodi encode e
 * decode devono lavorare sui byte[] invece che su String altrimenti il metodo
 * doFinal in decode lancia una exception legata al mancato padding
 */
public class AESCryptography extends CryptographyBaseClass {

    //private static String CYPHERALGORITHM = "PBEWithHmacSHA512AndAES_256";
    private static String CIPHERALGORITHM = "PBKDF2WithHmacSHA256";
    
    private static final int PASSWORD_ITERATIONS = 65536; // vs brute force
    private static final int KEY_LENGTH = 256;
    private static final int TIPICALLENGTH = 16;

    private char[] mPass = null;
    private byte[] mSalt = new byte[TIPICALLENGTH]; // for more confusion
    private byte[] ivBytes = null; //{0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

    private SecretKeySpec secret = null;	// Per ritornare la chiave in caso ne serva una rappresentazione 

    // Imposto il vettore del salt randomicamente ad ogni istanza della classe
    /**
     * Constructor
     */
    public AESCryptography() {
    }

    /**
     * Crea il cifrario a partire dallo stato interno impostato (password, salt e IV)
     * @param modeIsEncrypt true se cofifico, false se decodifico
     * @return Cihper per codificare o decodificare il testo passato
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     * @throws GeneralSecurityException
     */
    @Override
    public Cipher createCipher(boolean modeIsEncrypt) throws
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException {

        if (!modeIsEncrypt && ivBytes == null) {
            throw new IllegalStateException("ivBytes is null on decode");
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        int cipherMode = modeIsEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

        // Inizializzo il vettore IV
        if (ivBytes == null) {
            cipher.init(cipherMode, secret);
            
            AlgorithmParameters parameters = cipher.getParameters();
            ivBytes = parameters.getParameterSpec(IvParameterSpec.class).getIV();
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            cipher.init(cipherMode, secret, ivParameterSpec);
        }

        return cipher;
    }

//    private CipherOutputStream createCipherOutputStream(){
//	
//    }
    
    /**
     * Crea la secret key a partire dalla password e salt
     *
     * @throws java.security.GeneralSecurityException
     */
    @Override
    public void createKey() throws GeneralSecurityException{
        createKey(mPass, mSalt);
    }
    
    
    /**
     * Crea la secret key a partire dalla password e salt
     *
     * @throws java.security.GeneralSecurityException
     */
    @Override
    public void createKey(char[] pass, byte[] salt) throws GeneralSecurityException {
        if (pass == null) {
            throw new GeneralSecurityException("Password cannot be null");
        }

        if (salt == null) {
            throw new GeneralSecurityException("Salt cannot be null");
        }

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHERALGORITHM);
        PBEKeySpec pBEKeySpec = new PBEKeySpec(pass, salt, PASSWORD_ITERATIONS, KEY_LENGTH);

        SecretKey secretKey = secretKeyFactory.generateSecret(pBEKeySpec);
        secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    /**
     * Codifica il testo con la pasword impostata nella classe
     *
     * @param plainText
     * @return
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    @Override
    public byte[] encode(String plainText) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = createCipher(true);
        byte encodedBytes[] = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return encodedBytes;
    }

    /**
     * Decodifica il testo con la password impostata nella classe
     *
     * @param encodedText
     * @return
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    @Override
    public String decode(byte[] encodedText) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = createCipher(false);

        return new String(cipher.doFinal(encodedText), StandardCharsets.UTF_8);
    }

    /**
     * Rimuove completamente la password dallo stato interno (TODO: eliminare anche salt e IV?)
     */
    private void clearPass() {
        if (this.mPass == null) {
            return;
        }

        for (int i = 0; i < this.mPass.length; i++) {
            this.mPass[i] = '\0';
        }
        this.mPass = null;
    }

    /**
     * Restituisce la secret key legata ai parametri del cifrario
     * @return 
     */
    @Override
    public SecretKeySpec getSecretKey() {
        return secret;
    }

    /**
     * Imposta la chiave segreta
     * @param secretKeySpec 
     */
    @Override
    public void setSecretKey(SecretKeySpec secretKeySpec) {
        secret = secretKeySpec;
    }
    
    /**
     * Codifica un file a partire dallo stato interno impostato 
     * @param fileClearFileInputStream
     * @param fileEncodedOutputStream
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     * @throws GeneralSecurityException 
     */
    @Override
    public void encodeFile(FileInputStream fileClearFileInputStream, FileOutputStream fileEncodedOutputStream) throws
            IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException {
        Cipher cipher;
        cipher = createCipher(true);

        try (CipherOutputStream cos = new CipherOutputStream(fileEncodedOutputStream, cipher)) {
            int readByte = 0;
            byte[] buffer = new byte[1024];

            while ((readByte = fileClearFileInputStream.read(buffer)) != -1) {
                cos.write(buffer, 0, readByte);
            }
            cos.flush();
            fileClearFileInputStream.close();
        }
    }

    /**
     * Decodifica un file a partire dallo stato interno impostato
     * @param fileEncodedFileInputStream
     * @param fileClearOutputStream
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     * @throws GeneralSecurityException 
     */
    @Override
    public void decodeFile(FileInputStream fileEncodedFileInputStream, FileOutputStream fileClearOutputStream) throws
            IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException {

        Cipher cipher = createCipher(false);
        try (CipherInputStream cipherInputStream = new CipherInputStream(fileEncodedFileInputStream, cipher)) {
            int readByte = 0;
            byte[] buffer = new byte[1024];
            while ((readByte = cipherInputStream.read(buffer)) != -1) {
                fileClearOutputStream.write(buffer, 0, readByte);
            }
            fileClearOutputStream.flush();
            fileClearOutputStream.close();
        }
    }

    /**
     * Ritorna una copia del vettore di inizializzazione
     *
     * @return
     */
    @Override
    public byte[] getIVVector() {
        return Arrays.copyOf(ivBytes, ivBytes.length);
    }

    /**
     * Imposta il vettore di inizializzazione copiando i valori dal parametro
     *
     * @throws java.security.GeneralSecurityException
     */
    @Override
    public void setIVVector(byte[] iv) throws GeneralSecurityException {
        // TODO: Condizione strana, forse da togliere
        if (ivBytes != null && iv != null && iv.length != ivBytes.length) {
            throw new GeneralSecurityException();
        } else {
            ivBytes = Arrays.copyOf(iv, iv.length);
        }
    }

    /**
     * Restituisce il salt
     * @return salt
     */
    @Override
    public byte[] getSalt() {
        return Arrays.copyOf(mSalt, mSalt.length);
    }

    /**
     * Imposta il salt (TODO: reimpostare la password???)
     * @param salt Array di 16 byte contenete il salt da impostare. Se null ne genera uno casuale 
     * e lo imposta come parametro di crittografia interno
     */
    @Override
    public void setSalt(byte[] salt) {
        if (salt == null) {
            setRandomSalt();
        } else {
            this.mSalt = Arrays.copyOf(salt, salt.length);
        }
    }

    /**
     * Genera ed imposta lo stato interno con un salt generico (TODO: reimpostare la password???)
     */
    @Override
    public void setRandomSalt() {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(secureRandom.generateSeed(TIPICALLENGTH));
        secureRandom.nextBytes(mSalt);
    }

    /**
     * Imposta la password di cifratura con un salt casuale 
     * e crea la secret key
     * N.B. recuperare il SALT altrimenti non sarà possibile decifrare quanto 
     * è stato cifrato con questo oggetto
     * @param pass
     * @throws GeneralSecurityException 
     */
    @Override
    public void setPass(char[] pass) throws GeneralSecurityException {
        clearPass();
        this.mPass = Arrays.copyOf(pass, pass.length);
        
//        setRandomSalt();
//        createKey(mPass, mSalt);
    }

    /**
     * Imposta la password con il salt specificato e crea la secret key
     * @param pass
     * @param salt
     * @throws GeneralSecurityException 
     */
    @Override
    public void setPass(char[] pass, byte[] salt) throws GeneralSecurityException {
        clearPass();
        this.mPass = Arrays.copyOf(pass, pass.length);
       
        setSalt(salt);
//        createKey(mPass, mSalt);
    }

    /**
     * Imposta i parmetri segreti iniziali (password, salt e initial vector) necessari per il cifrario
     * e crea la secretKey 
     * @param pass
     * @param salt
     * @param iv
     * @throws GeneralSecurityException 
     */
    @Override
    public void initSecretParameters(char[] pass, byte[] salt, byte[] iv) throws GeneralSecurityException {
        setPass(pass, salt);
        setIVVector(iv);
        createKey(pass, salt);
    }

}
