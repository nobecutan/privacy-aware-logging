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

import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import org.slf4j.helpers.Util;

import ch.qos.logback.core.spi.ContextAwareBase;
import ch.qos.logback.core.spi.LifeCycle;

public class RsaEncSanitizerFactory extends ContextAwareBase implements IParamSanitizerFactory, LifeCycle {

	public class RsaEncSanitizer extends ParamEncryptingSanitizerBase {

		protected RsaEncSanitizer(String tagName,
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
			synchronized (cipher) {
				try {
					return cipher.doFinal(super.getCritical().getBytes());
				} catch (Exception cause) {
					addError("Failed to sanitize {" + tagName + "}.", cause);
					throw cause instanceof RuntimeException ? (RuntimeException) cause : new RuntimeException(cause);
				}
			}
		}

	}

	protected X509Certificate encCertificate;
	protected boolean started;
	protected Cipher cipher;
	protected boolean encryptCritical = false;
	protected String identifier = "rsa";
	protected boolean showSequenceNumber;

	@Override
	public IParamSanitizer create(String tagName, Object parameter, int start, int startOriginal, int endOriginal) {
		if (!isStarted()) {
			addError("The encrypting sanitizer " + getClass().getName() + " has not been started.");
			return null;
		}
		return new RsaEncSanitizer(tagName, parameter, start, startOriginal, endOriginal, identifier, showSequenceNumber);
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

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public void setShowSequenceNumber(boolean showSequenceNumber) {
		this.showSequenceNumber = showSequenceNumber;
	}

	@Override
	public void start() {
		if (context == null) {
			Util.report("RsaEncryptingSanitizer cannot be started w/o a context");
			throw new RuntimeException("RsaEncryptingSanitizer cannot be started w/o a context");
		}
		if (encCertificate == null) {
			addError("RsaEncryptingSanitizer cannot be started w/o an encryption certificate");
			throw new RuntimeException("RsaEncryptingSanitizer cannot be started w/o an encryption certificate");
		}
		try {
			cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, encCertificate.getPublicKey());
		} catch (Exception cause) {
			addError("Failed to initialize the cipher for " + getClass(), cause);
			throw cause instanceof RuntimeException ? (RuntimeException) cause
			    : new RuntimeException("Failed to initialize the cipher for " + getClass(), cause);
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
