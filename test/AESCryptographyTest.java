/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
//import org.junit.jupiter.api.AfterEach;
//import org.junit.jupiter.api.AfterAll;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.BeforeAll;
//import org.junit.jupiter.api.Test;
import static junit.framework.Assert.assertEquals;
import org.junit.Test;
import org.junit.*;
import static org.junit.jupiter.api.Assertions.*;

import SimpleAESEncryptionLib.*;

/**
 *
 * @author utente
 */
public class AESCryptographyTest {

    public AESCryptographyTest() {
    }

//    @BeforeAll
//    public static void setUpClass() {
//    }
//
//    @AfterAll
//    public static void tearDownClass() {
//    }
//
//    @BeforeEach
//    public void setUp() {
//    }
//
//    @AfterEach
//    public void tearDown() {
//    }
    
    
    /**
     * Test of encode method, of class AESCryptography.
     */
    @Test
    public void testEncodeStringMemory() throws Exception {
        System.out.println("encode");
        assertTrue(testEncodeDecodeString());
    }

//    /**
//     * Test of createCipher method, of class AESCryptography.
//     */
//    @Test
//    public void testCreateCipher() throws Exception {
//        System.out.println("createCipher");
//        boolean modeIsEncrypt = false;
//        AESCryptography instance = new AESCryptography();
//        Cipher expResult = null;
//        Cipher result = instance.createCipher(modeIsEncrypt);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        //fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of createKey method, of class AESCryptography.
//     */
//    @Test
//    public void testCreateKey() throws Exception {
//        System.out.println("createKey");
//        char[] pass = null;
//        byte[] salt = null;
//        AESCryptography instance = new AESCryptography();
//        instance.createKey(pass, salt);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of decode method, of class AESCryptography.
//     */
//    @Test
//    public void testDecode() throws Exception {
//        System.out.println("decode");
//        byte[] encodedText = null;
//        AESCryptography instance = new AESCryptography();
//        String expResult = "";
//        String result = instance.decode(encodedText);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setPass method, of class AESCryptography.
//     */
//    @Test
//    public void testSetPass_charArr() throws Exception {
//        System.out.println("setPass");
//        char[] pass = null;
//        AESCryptography instance = new AESCryptography();
//        instance.setPass(pass);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getSecretKey method, of class AESCryptography.
//     */
//    @Test
//    public void testGetSecretKey() {
//        System.out.println("getSecretKey");
//        AESCryptography instance = new AESCryptography();
//        SecretKeySpec expResult = null;
//        SecretKeySpec result = instance.getSecretKey();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setSecretKey method, of class AESCryptography.
//     */
//    @Test
//    public void testSetSecretKey() {
//        System.out.println("setSecretKey");
//        SecretKeySpec secretKeySpec = null;
//        AESCryptography instance = new AESCryptography();
//        instance.setSecretKey(secretKeySpec);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of encodeFile method, of class AESCryptography.
//     */
//    @Test
//    public void testEncodeFile() throws Exception {
//        System.out.println("encodeFile");
//        FileInputStream fileClearFileInputStream = null;
//        FileOutputStream fileEncodedOutputStream = null;
//        AESCryptography instance = new AESCryptography();
//        instance.encodeFile(fileClearFileInputStream, fileEncodedOutputStream);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of decodeFile method, of class AESCryptography.
//     */
//    @Test
//    public void testDecodeFile() throws Exception {
//        System.out.println("decodeFile");
//        FileInputStream fileEncodedFileInputStream = null;
//        FileOutputStream fileClearOutputStream = null;
//        AESCryptography instance = new AESCryptography();
//        instance.decodeFile(fileEncodedFileInputStream, fileClearOutputStream);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getIVVector method, of class AESCryptography.
//     */
//    @Test
//    public void testGetIVVector() {
//        System.out.println("getIVVector");
//        AESCryptography instance = new AESCryptography();
//        byte[] expResult = null;
//        byte[] result = instance.getIVVector();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setIVVector method, of class AESCryptography.
//     */
//    @Test
//    public void testSetIVVector() throws Exception {
//        System.out.println("setIVVector");
//        byte[] iv = null;
//        AESCryptography instance = new AESCryptography();
//        instance.setIVVector(iv);
//        // TODO review the generated test code and remove the default call to fail.
//
//        fail("The test case is a prototype.");
//
//    }
//
//    /**
//     * Test of getSalt method, of class AESCryptography.
//     */
//    @Test
//    public void testGetSalt() {
//        System.out.println("getSalt");
//        AESCryptography instance = new AESCryptography();
//        byte[] expResult = null;
//        byte[] result = instance.getSalt();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setSalt method, of class AESCryptography.
//     */
//    @Test
//    public void testSetSalt() {
//        System.out.println("setSalt");
//        byte[] salt = null;
//        AESCryptography instance = new AESCryptography();
//        instance.setSalt(salt);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setRandomSalt method, of class AESCryptography.
//     */
//    @Test
//    public void testSetRandomSalt() {
//        System.out.println("setRandomSalt");
//        AESCryptography instance = new AESCryptography();
//        instance.setRandomSalt();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setPass method, of class AESCryptography.
//     */
//    @Test
//    public void testSetPass_charArr_byteArr() throws Exception {
//        System.out.println("setPass");
//        char[] pass = null;
//        byte[] salt = null;
//        AESCryptography instance = new AESCryptography();
//        instance.setPass(pass, salt);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of initSecretParameters method, of class AESCryptography.
//     */
//    @Test
//    public void testInitSecretParameters() throws Exception {
//        System.out.println("initSecretParameters");
//        char[] pass = null;
//        byte[] salt = null;
//        byte[] iv = null;
//        AESCryptography instance = new AESCryptography();
//        instance.initSecretParameters(pass, salt, iv);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    /**
     * Metodo di ausilio per i test di cifratura e decifratura su file
     *
     * @param fileIn
     * @param fileOut
     * @param aesCryptography
     * @param cifratura
     * @throws FileNotFoundException
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private void cifraDecifra(String fileIn, String fileOut, InterfaceCryptography aesCryptography, boolean cifratura) throws FileNotFoundException, GeneralSecurityException, IOException {
        FileInputStream fin;
        FileOutputStream fos;
        fin = new FileInputStream(fileIn);
        fos = new FileOutputStream(fileOut);
        
        byte[] salt={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

        aesCryptography.setPass("pippopippo".toCharArray(),salt);
        //byte[] salt = aesCryptography.getSalt();

        if (cifratura) {
            aesCryptography.encodeFile(fin, fos);
        } else {
            aesCryptography.decodeFile(fin, fos);
        }

    }

    /**
     * Test per la codifica e decodifica di stringhe in base64
     *
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    private boolean testEncodeDecodeString() throws GeneralSecurityException, UnsupportedEncodingException {
        InterfaceCryptography aes1 = Base64Criptography.wrap(new AESCryptography());
        InterfaceCryptography aes2 = Base64Criptography.wrap(new AESCryptography());
        //AESCryptography aes2 = new AESCryptography();
        String plainText = "prova";

        aes1.setPass("pippopippo".toCharArray(), null);
        byte[] encoded = aes1.encode(plainText);
        // String decoded1=aes1.decode(encoded);

        // Salvo i parametri per generare la chiave segreta del primo oggetto
        byte[] iv1 = aes1.getIVVector();
        byte[] salt1 = aes1.getSalt();
        //SecretKeySpec k=aes1.getSecretKey();
        //aes2.setSecretKey(k);

        // Inizializzo la chiave segreta del secondo oggetto con i parametri del primo
        aes2.initSecretParameters("pippopippo".toCharArray(), salt1, iv1);
        //aes2.setIVVector(iv1);

        // Decodifico la stringa con il secondo oggetto
        String decoded = aes2.decode(encoded);
        System.out.printf("Stinga originaria: %s%n", plainText);
        System.out.printf("Stringa codificata: %s%n", new String(encoded, StandardCharsets.UTF_8));
        System.out.printf("Stinga decodificata: %s%n", decoded);

        return (plainText.equals(decoded));
    }

    /**
     * Metodo di ausilio ceh incapsula la modalità di cifratura e decifratura
     *
     * @throws GeneralSecurityException
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     * @throws IOException
     */
    @Test
    public void testCifraDecifraFile() throws GeneralSecurityException, GeneralSecurityException, UnsupportedEncodingException, IOException {
        InterfaceCryptography aesCipher = Base64Criptography.wrap(new AESCryptography());
//	    InterfaceCryptography aesCipher = new AESCryptography();
        aesCipher.setPass("pippo1234567890".toCharArray());
        String testoInChiaro="prova di testo da codificare1234"
                + "prova di testo da codificare,prova di testo da codificare,"
                + "prova di testo da codificare";
        byte[] testoCodificato = aesCipher.encode(testoInChiaro);
        String testoCodificatoString = new String(testoCodificato);
        System.out.format("Testo codificato: %s %n", testoCodificatoString);
        String testoDecodificato = aesCipher.decode(testoCodificato);
        System.out.format("Testo decodificato: %s %n", testoDecodificato);

        assertTrue(testoInChiaro.equals(testoDecodificato));
        
        InterfaceCryptography aesCryptography = new AESCryptography();
        String fileInput = "D:\\temp\\a_TODEL.mp4";
        String fileOutput = "D:\\temp\\a_TODEL.mp4_CIFRATO";
        String fileInputDecifrato = "D:\\temp\\a_TODEL.mp4_decifrato";
        
        cifraDecifra(fileInput, fileOutput, aesCryptography, true);
        cifraDecifra(fileOutput, fileInputDecifrato, aesCryptography, false);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        DigestInputStream dis1 = new DigestInputStream(new FileInputStream(fileInput), sha256);
        byte[] buffer = new byte[1024];
        while (dis1.read(buffer)!=-1) {
            // Leggo tutto il file ed aggiorno il digest
        }
        byte[] digest1 = dis1.getMessageDigest().digest();
        
        sha256.reset();
        DigestInputStream dis2 = new DigestInputStream(new FileInputStream(fileInputDecifrato), sha256);
        while (dis2.read(buffer)!=-1 ){
            
        }
        byte[] digest2 = dis2.getMessageDigest().digest();
        boolean retval=true;
        for(int i=0;i<digest1.length;i++){
            retval = retval && (digest1[i]==digest2[i]);
        }
        
        assertTrue(retval);
        
    }

    /**
     * Testa l'inizializzazione dell'IV
     *
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    private void testIV() throws GeneralSecurityException, UnsupportedEncodingException {
        AESCryptography aes1 = new AESCryptography();
        aes1.setPass("pippopippo".toCharArray());
        String plainText = "prova";
        aes1.encode(plainText);
        byte[] iv1 = aes1.getIVVector();

        AESCryptography aes2 = new AESCryptography();
        aes2.setPass("pippopippo".toCharArray());
        aes2.encode(plainText);
        byte[] iv2 = aes2.getIVVector();

        AESCryptography aes3 = new AESCryptography();
        aes3.setPass("pippopippo".toCharArray());
        aes3.encode(plainText);
        byte[] iv3 = aes3.getIVVector();

        System.out.printf("lunghezze IV %d - %d - %d %n", iv1.length, iv2.length, iv3.length);

        for (int i = 0; i < iv1.length; i++) {
            System.out.printf("Valori: %d - %d - %d%n", iv1[i], iv2[i], iv3[i]);
        }
    }

}
