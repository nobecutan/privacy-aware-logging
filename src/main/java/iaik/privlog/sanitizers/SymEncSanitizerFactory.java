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
package iaik.privlog.sanitizers;

import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.helpers.Util;

import ch.qos.logback.core.spi.ContextAwareBase;
import ch.qos.logback.core.spi.LifeCycle;

public class SymEncSanitizerFactory extends ContextAwareBase implements IParamSanitizerFactory, LifeCycle {

	public class SymEncSanitizer extends ParamEncryptingSanitizerBase {

		protected SymEncSanitizer(String tagName,
		                          Object parameter,
		                          int start,
		                          int startOriginal,
		                          int endOriginal,
		                          String identifier,
		                          boolean showSequenceNumber)
		{
			super(tagName, parameter, start, startOriginal, endOriginal, identifier, showSequenceNumber);
			equal = encryptCritical;
		}

		@Override
		public String getCritical() {
			if (critical == null) {
				critical = encryptCritical ? getSanitized() : super.getCritical();
			}
			return critical;
		}

		@Override
		protected byte[] getCipherText() {
			try {
				byte[] enc = cipher.doFinal(super.getCritical().getBytes());
				if (updateIV) {
					incIV();
					cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv), random);
				}
				return enc;
			} catch (Exception cause) {
				addError("Failed to sanitize {" + tagName + "}.", cause);
				throw cause instanceof RuntimeException ? (RuntimeException) cause : new RuntimeException(cause);
			}
		}

		public void incIV() {
			for (int i = iv.length - 1; i >= 0; i--) {
				iv[i]++;
				if (iv[i] != 0) break;
			}
		}
	}

	protected X509Certificate encCertificate;
	protected boolean started;
	protected Cipher cipher;
	protected Base64 base64 = new Base64();
	protected boolean encryptCritical = false;
	protected OutputStream keyInfoOutputSream = System.err;
	protected String algorithm = "AES/GCM/NoPadding";
	protected SecretKey secretKey;
	protected byte[] iv;
	protected SecureRandom random;
	protected int blockSize;
	protected boolean updateIV;
	protected String identifier = "sym";
	protected boolean showSequenceNumber;

	@Override
	public IParamSanitizer create(String tagName, Object parameter, int start, int startOriginal, int endOriginal) {
		if (!isStarted()) {
			addError("The encrypting sanitizer " + getClass().getName() + " has not been started.");
			return null;
		}
		return new SymEncSanitizer(tagName, parameter, start, startOriginal, endOriginal, identifier, showSequenceNumber);
	}

	public X509Certificate getEncCertificate() {
		return encCertificate;
	}

	public void setEncCertificate(X509Certificate encCertificate) {
		this.encCertificate = encCertificate;
	}

	public boolean isEncryptCritical() {
		return encryptCritical;
	}

	public void setEncryptCritical(boolean encryptCritical) {
		this.encryptCritical = encryptCritical;
	}

	public OutputStream getKeyInfoOutputSream() {
		return keyInfoOutputSream;
	}

	public void setKeyInfoOutputSream(OutputStream keyInfoOutputSream) {
		this.keyInfoOutputSream = keyInfoOutputSream;
	}

	public boolean isUpdateIV() {
		return updateIV;
	}

	public void setUpdateIV(boolean updateIV) {
		this.updateIV = updateIV;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
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

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public void setShowSequenceNumber(boolean showSequenceNumber) {
		this.showSequenceNumber = showSequenceNumber;
	}

	@Override
	public void start() {
		if (context == null) {
			Util.report("AesEncryptingSanitizer cannot be started w/o a context");
			throw new RuntimeException("AesEncryptingSanitizer cannot be started w/o a context");
		}
		if (keyInfoOutputSream == null) {
			addError("AesEncryptingSanitizer cannot be started w/o an encryption certificate");
			throw new RuntimeException("AesEncryptingSanitizer cannot be started w/o an encryption certificate");
		}
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		StringBuffer keyInfo = new StringBuffer("Starting Date: ");
		keyInfo.append(df.format(new Date())).append(System.lineSeparator());
		String startingDate = keyInfo.toString();
		int initLength = startingDate.length();

		try {
			cipher = Cipher.getInstance(algorithm);
			blockSize = cipher.getBlockSize();
			if (random == null) {
				random = new SecureRandom();
			}
			if (secretKey == null) {
				String keyAlg = algorithm.split("/")[0];
				KeyGenerator generator = KeyGenerator.getInstance(keyAlg);
				generator.init(blockSize * 8, random);
				secretKey = generator.generateKey();
				keyInfo.append("Secret Key: ").append(base64.encodeToString(secretKey.getEncoded()))
				    .append(System.lineSeparator());
			}
			if (iv == null) {
				iv = new byte[blockSize];
				random.nextBytes(iv);
				keyInfo.append("InitVector: ").append(base64.encodeToString(iv)).append(System.lineSeparator());
			}
			if (keyInfo.length() > initLength) {
				// Output key info
				byte[] keyInfoBytes = keyInfo.toString().getBytes();
				if (encCertificate != null) {
					Cipher keyCipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
					keyCipher.init(Cipher.ENCRYPT_MODE, encCertificate.getPublicKey());
					keyInfo = new StringBuffer();
					keyInfo.append(base64.encodeAsString(keyCipher.doFinal(keyInfoBytes)));
					keyInfo.append(System.lineSeparator()).append(System.lineSeparator());
					keyInfoBytes = keyInfo.toString().getBytes();
				}
				keyInfoOutputSream.write(keyInfoBytes);
				keyInfoOutputSream.flush();
			}
			keyInfoOutputSream.close();
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv), random);
		} catch (Exception cause) {
			addError("Failed to initialize the cipher '" + algorithm + "' for " + getClass(), cause);
			throw cause instanceof RuntimeException ? (RuntimeException) cause
			    : new RuntimeException("Failed to initialize the cipher '" + algorithm + "' for " + getClass(), cause);
		}

		started = true;
	}

	@Override
	public void stop() {
		started = false;

	}

	@Override
	public boolean isStarted() {
		return started;
	}

}
