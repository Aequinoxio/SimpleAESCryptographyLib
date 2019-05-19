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
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import SimpleAESEncryptionLib.*;

/**
 * Classe di test  per verificare che i metodi funzionino
 * Da cancellare quando la libreria sarà stabile
 * @author utente
 */
public class AESEncryption {

    /**
     * @param args the command line arguments
     * @throws java.io.IOException
     */
    
    public static void main(String[] args) throws IOException {
	
	try {
	    //testCifraDecifraFile();
	    
	    //testIV();
	    testEncodeDecodeString();
	} catch (GeneralSecurityException | UnsupportedEncodingException ex) {
	    Logger.getLogger(AESEncryption.class.getName()).log(Level.SEVERE, null, ex);
	}
	
    }
    
    private static void testCifraDecifraFile() throws GeneralSecurityException, GeneralSecurityException, UnsupportedEncodingException, IOException{
       	    InterfaceCryptography aesCipher = Base64Criptography.wrap(new AESCryptography());
//	    InterfaceCryptography aesCipher = new AESCryptography();
	    aesCipher.setPass("pippo1234567890".toCharArray());
	    byte[] testoCodificato=aesCipher.encode("prova di testo da codificare1234"
		    + "prova di testo da codificare,prova di testo da codificare,"
		    + "prova di testo da codificare");
	    String testoCodificatoString=new String(testoCodificato);
	    System.out.format("Testo codificato: %s %n", testoCodificatoString);
	    String testoDecodificato=aesCipher.decode(testoCodificato);
	    System.out.format("Testo decodificato: %s %n", testoDecodificato);
	    
	    InterfaceCryptography aesCryptography = new AESCryptography();
	    cifraDecifra("d:\\SysnativeBSODApps.exe","d:\\file_cifrato.txt", aesCryptography, true);
	    cifraDecifra("d:\\file_cifrato.txt","d:\\SysnativeBSODApps.exe_decifrato.txt", aesCryptography, false);
 
    }
    
    private static void cifraDecifra(String fileIn, String fileOut,InterfaceCryptography aesCryptography, boolean cifratura) throws FileNotFoundException, GeneralSecurityException, IOException{
	FileInputStream fin;
	FileOutputStream fos;
        fin = new FileInputStream(fileIn);
        fos = new FileOutputStream(fileOut);
	    
	aesCryptography.setPass("pippopippo".toCharArray());

	if(cifratura)
	    aesCryptography.encodeFile(fin, fos);
	else
	    aesCryptography.decodeFile(fin, fos);
	
    }
    
    private static void testIV() throws GeneralSecurityException, UnsupportedEncodingException{
	AESCryptography aes1 = new AESCryptography();
	aes1.setPass("pippopippo".toCharArray());
        String plainText="prova";
        aes1.encode(plainText);
	byte[] iv1=aes1.getIVVector();

	AESCryptography aes2 = new AESCryptography();
	aes2.setPass("pippopippo".toCharArray());
        aes2.encode(plainText);
	byte[] iv2=aes2.getIVVector();

	AESCryptography aes3 = new AESCryptography();
	aes3.setPass("pippopippo".toCharArray());
        aes3.encode(plainText);
        byte[] iv3=aes3.getIVVector();
	
	System.out.printf("lunghezze IV %d - %d - %d %n", iv1.length,iv2.length,iv3.length);
	
	for (int i=0;i<iv1.length;i++){
            System.out.printf("Valori: %d - %d - %d%n",iv1[i],iv2[i],iv3[i]);
	}
    }
    
    /**
     * codifico con un oggetto e decodifico con un altro
     */
    private static void testEncodeDecodeString() throws GeneralSecurityException, UnsupportedEncodingException{
        InterfaceCryptography aes1 = Base64Criptography.wrap(new AESCryptography());
        InterfaceCryptography aes2 = Base64Criptography.wrap(new AESCryptography());
        //AESCryptography aes2 = new AESCryptography();
        String plainText="prova";
        
        aes1.setPass("pippopippo".toCharArray(), null);
        byte[] encoded=aes1.encode(plainText);
        // String decoded1=aes1.decode(encoded);
        
        // Salvo i parametri per generare la chiave segreta del primo oggetto
        byte[] iv1=aes1.getIVVector();
        byte[] salt1=aes1.getSalt();
        //SecretKeySpec k=aes1.getSecretKey();
        //aes2.setSecretKey(k);
        
        // Inizializzo la chiave segreta del secondo oggetto con i parametri del primo
        aes2.initSecretParameters("pippopippo".toCharArray(), salt1, iv1);
        //aes2.setIVVector(iv1);
     
        // Decodifico la stringa con il secondo oggetto
        String decoded=aes2.decode(encoded);
        System.out.printf("Stinga originaria: %s%n",plainText);
        System.out.printf("Stringa codificata: %s%n",new String(encoded,StandardCharsets.UTF_8));
        System.out.printf("Stinga decodificata: %s%n",decoded);
        
    }
}
