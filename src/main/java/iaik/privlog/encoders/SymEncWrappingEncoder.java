/**
 * Copyright 2016 Christof Rath <christof.rath@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package iaik.privlog.encoders;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class SymEncWrappingEncoder extends WrappingEncoderBase<ILoggingEvent> {
	public static final int DEFAULT_IV_SIZE = 12;
	public static final int DEFAULT_MAC_BUFFER_SIZE = 128;
	public static final String DEFAULT_SYMMETRIC_ALGORITHM = "AES/CCM/NoPadding";
	public static final String DEFAULT_KEY_WRAPPING_ALGORITHM = "RSA/None/OAEPWithSHA1AndMGF1Padding";
	public static final String PREFIX_KEY_INFO = "Key Info: ";
	public static final String PREFIX_SECRET_KEY = "Secret Key: ";
	public static final String PREFIX_INIT_VECTOR = "InitVector: ";

	protected X509Certificate encCertificate;
	protected Base64 base64 = new Base64();
	protected String symmetricAlgorithm = DEFAULT_SYMMETRIC_ALGORITHM;
	protected String keyWrappingAlgorithm = DEFAULT_KEY_WRAPPING_ALGORITHM;
	protected SecretKey secretKey;
	protected byte[] iv;
	protected SecureRandom random;
	protected int blockSize;
	protected boolean updateIV;
	protected Cipher cipher;
	private CipherOutputStream cipherOutputStream;

	public void setEncCertificate(X509Certificate encCertificate) {
		this.encCertificate = encCertificate;
	}

	public void setUpdateIV(boolean updateIV) {
		this.updateIV = updateIV;
	}

	public void setSymmetricAlgorithm(String algorithm) {
		this.symmetricAlgorithm = algorithm;
	}

	public void setKeyWrappingAlgorithm(String keyWrappingAlgorithm) {
		this.keyWrappingAlgorithm = keyWrappingAlgorithm;
	}

	public void setSecretKey(SecretKey secretKey) {
		this.secretKey = secretKey;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

	public void setRandom(SecureRandom random) {
		this.random = random;
	}

	@Override
	public void init(OutputStream os)
	    throws IOException
	{
		StringBuffer keyInfo = new StringBuffer();
		byte[] keyInfoBytes = null;
		try {
			cipher = Cipher.getInstance(symmetricAlgorithm);
			blockSize = cipher.getBlockSize();
			if (random == null) {
				random = new SecureRandom();
			}
			if (secretKey == null) {
				String keyAlg = symmetricAlgorithm.split("/")[0];
				KeyGenerator generator = KeyGenerator.getInstance(keyAlg);
				generator.init(blockSize * 8, random);
				secretKey = generator.generateKey();
				keyInfo.append(PREFIX_SECRET_KEY).append(base64.encodeToString(secretKey.getEncoded())).append("\n");
			}
			if (iv == null) {
				iv = new byte[DEFAULT_IV_SIZE];
				random.nextBytes(iv);
				keyInfo.append(PREFIX_INIT_VECTOR).append(base64.encodeToString(iv)).append("\n");
			}
			if (keyInfo.length() > 0) {
				// Output key info
				keyInfoBytes = keyInfo.toString().getBytes();
				if (encCertificate != null) {
					Cipher keyCipher = Cipher.getInstance(keyWrappingAlgorithm);
					keyCipher.init(Cipher.ENCRYPT_MODE, encCertificate.getPublicKey());
					keyInfo = new StringBuffer(PREFIX_KEY_INFO);
					keyInfo.append(base64.encodeAsString(keyCipher.doFinal(keyInfoBytes)));
					keyInfo.append("\n");
					keyInfoBytes = keyInfo.toString().getBytes();
				}
				os.write(keyInfoBytes);
				os.write(new byte[DEFAULT_MAC_BUFFER_SIZE]);
				os.flush();
			}
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv), random);
			cipherOutputStream = new CipherOutputStream(os, cipher);
			super.init(cipherOutputStream);
		} catch (Exception cause) {
			addError("Failed to initialize the cipher '" + symmetricAlgorithm + "' for " + getClass(), cause);
			if (cause instanceof IOException) {
				throw (IOException) cause;
			}
			throw cause instanceof RuntimeException ? (RuntimeException) cause : new RuntimeException(
			    "Failed to initialize the cipher '" + symmetricAlgorithm + "' for " + getClass(), cause);
		}
	}

	@Override
	public void close()
	    throws IOException
	{
		super.close();
		cipherOutputStream.close();
//		AlgorithmParameters params = cipher.getParameters();
//		GCMParameterSpec specs = (GCMParameterSpec) params.getParameterSpec(GCMParameterSpec.class);
//		cipher.
//		mac = specs.getMac();
//		System.out.println("MAC block: " + Util.toString(mac));

	}
}
