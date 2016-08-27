package mobi.suishi.security;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class AESCrypto {
	private static final String TAG = "AESCrypto";
    
	/**
	 * V1
	 * Encrypted file format
	 * |Magic code 4 byts|Version 1 byte|Sale size 1 bytes|Sale data|Iv size 1 bytes|initial iv|
	 * |Block, the IV comes from the last part of previous block. The iv size is defined in the head| 
	 * 
	 * V2 GZip and then encrypt
	 * Encrypted file format
	 * |Magic code 4 bytes|Version 1 byte|Sale size 1 bytes|Sale data|Iv size 1 bytes|initial iv|is_gizp 1 byte|
	 * |Block, the IV comes from the last part of previous block. The iv size is defined in the head| 
	 */
	private static final byte[] MAGIC_CODE = {'D', 'A', 'E','R'}; //EADE
	private static final byte VERSION = 2;
	
	private static final String PBKDF2_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
	private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

	private static int KEY_LENGTH = 256;
	// minimum values recommended by PKCS#5, increase as necessary
	private static int ITERATION_COUNT = 1000;
	private static final int PKCS5_SALT_LENGTH = 8;
	private static SecureRandom random = new SecureRandom();

	public static void encryptFile(File sourceFile, File encrypfile, String keyStr, boolean isGZip) throws Exception {
		InputStream inputStream = null;
		OutputStream outputStream = null;

		try {
			inputStream = new FileInputStream(sourceFile);
			outputStream = new FileOutputStream(encrypfile);
			encryptFile(inputStream, outputStream, keyStr, isGZip);

			outputStream.close();
			outputStream = null;

			inputStream.close();
			inputStream = null;

		} catch (Exception e) {
			throw e;
		} finally {
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
				}
			}
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
				}
			}
		}
	}

	/**
	* If encounter "java.security.InvalidKeyException: Illegal key size", 
	* we need install ${java.home}/jre/lib/security/ to ${java.home}/jre/lib/security/ 。
	* Refer to http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
	*/
	public static void encryptFile(InputStream inputStream, OutputStream outputStream, String keyStr, boolean isGZip) throws Exception {
		byte[] salt = generateSalt(false);
		SecretKey key =  deriveKeyPbkdf2(salt, keyStr);

		OutputStream wrappedOutstream = outputStream;
		DataOutputStream dos = null;

		try {
			//Write headers
			dos = new DataOutputStream(outputStream);
			dos.write(MAGIC_CODE);
			dos.writeByte(VERSION);
			if (salt != null && salt.length >0) {
				dos.writeByte(salt.length);
				dos.write(salt);
			}
			else {
				dos.writeByte(0);
			}

			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			byte[] iv = generateIv(cipher.getBlockSize(), false);
			if (iv != null && iv.length > 0) {
				dos.writeByte(iv.length);
				dos.write(iv);
			}
			else {
				dos.writeByte(0);
			}
			
			dos.writeBoolean(isGZip);
			
			//Write content
			IvParameterSpec ivParams = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
			wrappedOutstream = new CipherOutputStream(wrappedOutstream, cipher);

			if (isGZip) {
				wrappedOutstream = new GZIPOutputStream(wrappedOutstream);
			}
			
			byte[] cache = new byte[1024];
			int nRead = 0;
			while ((nRead = inputStream.read(cache)) != -1) {
				wrappedOutstream.write(cache, 0, nRead);
			}

			wrappedOutstream.close();
			wrappedOutstream = null;
			
			dos.close();
			dos = null;

		} catch (Exception e) {
			throw e;
		} finally {
			if (dos != null) {
				try {
					dos.close();
				} catch (IOException e) {
				}
			}

			if (wrappedOutstream != null) {
				try {
					wrappedOutstream.close();
				} catch (IOException e) {
				}
			}
		}
	}

	public static void decryptFile(File sourceFile, File decryptFile, String keyStr) throws Exception {
		InputStream inputStream = null;
		OutputStream outputStream = null;

		try {
			inputStream = new FileInputStream(sourceFile);
			outputStream = new FileOutputStream(decryptFile);

			decryptFile(inputStream, outputStream, keyStr);

			outputStream.close();
			outputStream = null;

			inputStream.close();
			inputStream = null;
		} catch (Exception e) {
			throw e;
		} finally {
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
				}
			}
		}
	}

	public static byte[] decryptFile(File sourceFile, String keyStr) throws Exception {
		byte[] plainData = null;

		InputStream inputStream = null;
		ByteArrayOutputStream outputStream = null;

		try {
			inputStream = new FileInputStream(sourceFile);
			outputStream = new ByteArrayOutputStream();

			decryptFile(inputStream, outputStream, keyStr);
			plainData = outputStream.toByteArray();

			outputStream.close();
			outputStream = null;

			inputStream.close();
			inputStream = null;
		} catch (Exception e) {
			throw e;
		} finally {
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
				}
			}
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
				}
			}
		}

		return plainData;
	}

	public static void decryptFile(InputStream inputStream, OutputStream outputStream, String keyStr) throws Exception {
		if (inputStream == null || outputStream == null) {
			return;
		}

		DataInputStream dis = null;
		InputStream wrappedInputstream = inputStream;
		try {
			//Read headers
			dis = new DataInputStream(inputStream);
			byte[] magicCode = new byte[MAGIC_CODE.length];
			dis.read(magicCode);
			if (compareByteArray(magicCode, MAGIC_CODE)) {
				int version = dis.readByte();
				int saltSize = dis.readByte();

				byte[] salt = null;
				if (saltSize > 0) {
					salt = new byte[saltSize];
					dis.read(salt);
				}

				int ivSize = dis.readByte();
				byte[] iv = null;
				if (ivSize >0) {
					iv = new byte[ivSize];
					dis.read(iv);
				}
				
				boolean isGZip = false;
				if (version >= VERSION) {
					isGZip = dis.readBoolean();
				}

				SecretKey key = deriveKeyPbkdf2(salt, keyStr);
				IvParameterSpec ivParams = new IvParameterSpec(iv);
				Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
				cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
				
				//Read content
				wrappedInputstream = new CipherInputStream(wrappedInputstream, cipher);
				if (isGZip) {
					wrappedInputstream = new GZIPInputStream(wrappedInputstream);
				}
			}
			else {
				//Restore read "magicCode" bytes
				outputStream.write(magicCode);
			}

			byte [] buffer = new byte [1024];
			int r;
			while ((r = wrappedInputstream.read(buffer)) >= 0) {
				outputStream.write(buffer, 0, r);
			}

			wrappedInputstream.close();
			wrappedInputstream = null;

			dis.close();
			dis = null;

		} catch (Exception e) {
			throw e;
		} finally {
			if (wrappedInputstream != null) {
				try {
					wrappedInputstream.close();
				} catch (IOException e) {
				}
			}			

			if (dis != null) {
				try {
					dis.close();
				} catch (IOException e) {
				}
			}
		}
	}

	public static String toHex(byte[] bytes) {
		StringBuffer buff = new StringBuffer();
		for (byte b : bytes) {
			buff.append(String.format("%02X", b));
		}

		return buff.toString();
	}

	private static SecretKey deriveKeyPbkdf2(byte[] salt, String keyStr) {
		try {
//			long start = System.currentTimeMillis();
			KeySpec keySpec = new PBEKeySpec(keyStr.toCharArray(), salt,
					ITERATION_COUNT, KEY_LENGTH);
			SecretKeyFactory keyFactory = SecretKeyFactory
					.getInstance(PBKDF2_DERIVATION_ALGORITHM);
			byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
			//			Log.d(TAG, "key bytes: " + toHex(keyBytes));

			SecretKey result = new SecretKeySpec(keyBytes, "AES");
			//			long elapsed = System.currentTimeMillis() - start;
			//			Log.d(TAG, String.format("PBKDF2 key derivation took %d [ms].",
			//					elapsed));

			return result;
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] generateIv(int length, boolean zero) {
		byte[] b = new byte[length];
		
		if (zero) {
			for (int i = 0; i < length; i++)
				b[i] = (byte)0;
		} else {
			random.nextBytes(b);
		}
		
		return b;
	}

	private static byte[] generateSalt(boolean zero) {
		byte[] b = new byte[PKCS5_SALT_LENGTH];
		
		if (zero) {
			for (int i = 0; i < PKCS5_SALT_LENGTH; i++)
				b[i] = (byte)0;
		} else {
			random.nextBytes(b);
		}
		
		return b;
	}

	private static boolean compareByteArray(byte[] src, byte[] dst) {
		if (src == null && dst == null) {
			return true;
		}
		else if (src == null || dst == null) {
			return false;
		}

		if (src.length != dst.length) {
			return false;
		}

		for (int i=0; i<src.length; i++) {
			if (src[i] != dst[i]) {
				return false;
			}
		}

		return true;
	}
	
	
    public static byte[] aesEncryptToBytes(String content, String encryptKey) throws Exception { 
		byte[] salt = generateSalt(true);
		SecretKey key =  deriveKeyPbkdf2(salt, encryptKey);
      				
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);  
		
        byte[] iv = generateIv(cipher.getBlockSize(), true);
		IvParameterSpec ivParams = new IvParameterSpec(iv);		

		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"), ivParams);  
          
        return cipher.doFinal(content.getBytes("utf-8"));  
    }  
    
    
    
    public static String aesEncryptToBase64(String content, String encryptKey) throws Exception {  
        return Base64.encodeToString(aesEncryptToBytes(content, encryptKey), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }     
    
    
    public static String aesDecryptByBytes(byte[] content, String decryptKey) throws Exception {  
		byte[] salt = generateSalt(true);
		SecretKey key =  deriveKeyPbkdf2(salt, decryptKey);
      				
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);  
		
        byte[] iv = generateIv(cipher.getBlockSize(), true);
		IvParameterSpec ivParams = new IvParameterSpec(iv);		

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"), ivParams);  
        byte[] decryptBytes = cipher.doFinal(content);  
          
        return new String(decryptBytes);  
    } 
    
    public static String aesDecryptByBase64(String content, String decryptKey) throws Exception {
    	return aesDecryptByBytes(Base64.decode(content, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING), decryptKey);  
    }  
    
    
    public static void main( String[] args ) {
    	try {
    		byte[] a = AESCrypto.aesEncryptToBytes("123456789012345", "1234567");
    		String b = AESCrypto.aesDecryptByBytes(a, "1234567");
    		
    		String c = AESCrypto.aesEncryptToBase64("123456789012345", "1234567");
    		String d = AESCrypto.aesDecryptByBase64(c, "1234567");
    		
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    }
    
}
