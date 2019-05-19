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
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;



/**
 *
 * @author utente
 */
public class Base64Criptography implements InterfaceCryptography{
    private InterfaceCryptography cryptography;

    public Base64Criptography(InterfaceCryptography cryptography) {
	this.cryptography = cryptography;
    }
    
    public static Base64Criptography wrap (InterfaceCryptography crypto){
	return new Base64Criptography(crypto);
    }
    
    @Override
    public byte [] encode(String plaintext) throws GeneralSecurityException, UnsupportedEncodingException{
	byte[] encoded = cryptography.encode(plaintext);
	return Base64.getEncoder().encode(encoded);
    }
    
    @Override
    public String decode(byte [] encodedtext)throws GeneralSecurityException, UnsupportedEncodingException{
	byte[] encodedBytes= Base64.getDecoder().decode(encodedtext);
	return cryptography.decode(encodedBytes);
    }

    @Override
    public SecretKeySpec getSecretKey() {
	return cryptography.getSecretKey();
    }

    @Override
    public void setPass(char[] pass) throws GeneralSecurityException {
	cryptography.setPass(pass);
    }

    @Override
    public Cipher createCipher(boolean modeIsEncrypt) throws 
	    NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
	    InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException{
	return cryptography.createCipher(modeIsEncrypt);
    }

    @Override
    public void encodeFile(FileInputStream fileClearFileInputStream, FileOutputStream fileEncodedOutputStream) throws 
	    IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
	    InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException {
	cryptography.encodeFile(fileClearFileInputStream, fileEncodedOutputStream);
    }

    @Override
    public void decodeFile(FileInputStream fileEncodedFileInputStream, FileOutputStream fileClearOutputStream) throws 
	    IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
	    InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException, GeneralSecurityException {
	cryptography.decodeFile(fileEncodedFileInputStream, fileClearOutputStream);
    }

    @Override
    public void setSecretKey(SecretKeySpec secretKeySpec) {
        cryptography.setSecretKey(secretKeySpec);
    }

    @Override
    public byte[] getSalt() {
        return cryptography.getSalt();
    }

    @Override
    public void setSalt(byte[] salt) {
        cryptography.setSalt(salt);
    }

    @Override
    public byte[] getIVVector() {
        return cryptography.getIVVector();
    }

    @Override
    public void setIVVector(byte[] iv) throws GeneralSecurityException {
        cryptography.setIVVector(iv);
    }

    @Override
    public void setPass(char[] pass, byte[] salt) throws GeneralSecurityException {
        cryptography.setPass(pass, salt);
    }

    @Override
    public void createKey(char[] pass, byte[] salt) throws GeneralSecurityException {
        cryptography.createKey(pass, salt);
    }

    @Override
    public void setRandomSalt() {
        cryptography.setRandomSalt();
    }

    @Override
    public void initSecretParameters(char[] pass, byte[] salt, byte[] iv) throws GeneralSecurityException {
        cryptography.initSecretParameters(pass, salt, iv);
    }

    @Override
    public void createKey() throws GeneralSecurityException {
        cryptography.createKey();
    }
}
