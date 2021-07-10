import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAUtil {

	private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCglgL/ncBTGt4FKvsYVCQ0XHyapon1w+d8Aw78svb0ygxixLGUEuzIXDVx385/f7Ev68cJm0C7nCRlA5ubLoWK3FFrsRtU/NBe0EOsqZ8qqXcYeMStjavRZVtmsjjuG6pOBO/VoBRzv+Vpvr0/mI7cUBzJKLRSb9HKEoYKtMkdxQIDAQAB";
	private static String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKCWAv+dwFMa3gUq+xhUJDRcfJqmifXD53wDDvyy9vTKDGLEsZQS7MhcNXHfzn9/sS/rxwmbQLucJGUDm5suhYrcUWuxG1T80F7QQ6ypnyqpdxh4xK2Nq9FlW2ayOO4bqk4E79WgFHO/5Wm+vT+YjtxQHMkotFJv0coShgq0yR3FAgMBAAECf1iabI0dPUCdUmMHlAOYaWF6pkWuHfC8ZrzF8z76f8gQs0TLwi8xQfRK7DIoiodOrTUDoo5qWw0o2eviUbkNsiBKZzoTSCRzrN6yZruA27yWFzYy8U5JdJmpZaaIygBggEnp2QdXt6e+PswcMbe2Crn7xPixjMvFRvbrBwk0ITkCQQDmEDqfxBeXB1xTFnnfzmH+UT2vlzHQUO/8It50869TKV6VfAOrgO9OWOw0DF0ttlngJmpB+ijxfiQp3t+71GM9AkEAsrCfNZKnc7VlfvNUfYfacI7i3qWLopoQxhxTzesDlGSLAKY4AqEdNXeTGW6XX/RC9S4u8KgOof0iKBnigtmtKQJBAIkcTvP8l9qIpntWP9gkVb6NiGfngeaW9g+ccFvfBzRWyWnpeP5zXyugT1VNsRKXRMUT3+vmPRR/iunxTAHTODkCQE1XYTHA7jWI2AtgqrtCp+t8DPotUQjqAkSdUjCYfg4mjnuTdj69GXVg8gxZ768afDi+6pZDR0IZ3ETbH01fhjECQQCXiEQMVfE2xc8EY87QXE62PZODUm1F/v7hZfy4jsDDsOTPEH/N37UKtb1B2zUn5WVmBZgThhls9hKTK8a6BiV1";

	public static PublicKey getPublicKey(String base64PublicKey) {
		PublicKey publicKey = null;
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return publicKey;
	}

	public static PrivateKey getPrivateKey(String base64PrivateKey) {
		PrivateKey privateKey = null;
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			privateKey = keyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return privateKey;
	}

	public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException,
			InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
		return cipher.doFinal(data.getBytes());
	}

	public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(cipher.doFinal(data));
	}

	public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException,
			InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
	}

	public static void main(String[] args)
			throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
		try {
			String encryptedString = Base64.getEncoder().encodeToString(encrypt("Dhiraj is the author", publicKey));
			System.out.println(encryptedString);
			encryptedString="RfCSfefyYlDSQbnEf9iQe6YcTsdO3Yrn9rsHSrjfwiz+fxVUk3+1BrM9srTh7NXvGJokvsy/SiKt5kHj277MHXcTJz+wIlAiZ+bKKOgaDlCER0U2CmB9ThReVQtywa1bcqgxqgtqAziNEi/XcG5RNvvCQwL3AYe3Wrr2iprbRDs=";
			String decryptedString = RSAUtil.decrypt(encryptedString, privateKey);
			System.out.println(decryptedString);
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		}

	}
}
