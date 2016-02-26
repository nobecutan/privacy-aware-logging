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

import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;

import ch.qos.logback.core.spi.ContextAwareBase;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class BlindingSanitizerFactory extends ContextAwareBase implements IParamSanitizerFactory {
	public class BlindingSanitizer extends ParamSanitizerBase {

		protected String critical;

		public BlindingSanitizer(String tag, Object parameter, int start, int startOriginal, int endOriginal) {
			super(tag, parameter, start, startOriginal, endOriginal);
			equal = isMaskCritical();
		}

		@Override
		public String getCritical() {
			if (critical == null) {
				critical = isMaskCritical() ? getSanitized() : super.getCritical();
			}
			return critical;
		}

		@Override
		public String getSanitized() {
			if (sanitized == null) {
				if (mac != null) {
					sanitized = base64.encodeToString(mac.doFinal(super.getCritical().getBytes()));
				} else if (digest != null) {
					sanitized = base64.encodeToString(digest.digest(super.getCritical().getBytes()));
				} else if (blindingMask != null) {
					sanitized = blindingMask;
				} else {
					sanitized = "[" + tagName + "]";
				}
			}
			return sanitized;
		}
	}

	public static final String BLINDING_MASK = "*****";

	protected String blindingMask = BLINDING_MASK;
	protected MessageDigest digest;
	protected Mac mac;
	protected Base64 base64;
	protected boolean maskCritical = false;

	@Override
	public BlindingSanitizer create(String tagName, Object parameter, int start, int startOriginal, int endOriginal) {
		return new BlindingSanitizer(tagName, parameter, start, startOriginal, endOriginal);
	}

	public String getBlindingMask() {
		return blindingMask;
	}

	public BlindingSanitizerFactory setBlindingMask(String blindingMask) {
		this.blindingMask = blindingMask;
		return this;
	}

	public void setDigest(MessageDigest digest) {
		this.digest = digest;
		base64 = new Base64();
	}

	public void setDigest(String algorithm) {
		try {
			digest = MessageDigest.getInstance(algorithm);
			base64 = new Base64();
		} catch (Exception cause) {
			addError("Failed to initialize the message digest with algorithm '" + algorithm + "' for " + getClass(), cause);
			throw cause instanceof RuntimeException ? (RuntimeException) cause : new RuntimeException(
			    "Failed to initialize the message digest with algorithm '" + algorithm + "' for " + getClass(), cause);
		}
	}

	public void setMac(Mac mac) {
		this.mac = mac;
		base64 = new Base64();
	}

	public void setMac(String algorithm, SecretKey secretKey) {
		try {
			mac = Mac.getInstance(algorithm);
			mac.init(secretKey);
			base64 = new Base64();
		} catch (Exception cause) {
			addError("Failed to initialize the MAC with algorithm '" + algorithm + "' for " + getClass(), cause);
			throw cause instanceof RuntimeException ? (RuntimeException) cause : new RuntimeException(
			    "Failed to initialize the MAC with algorithm '" + algorithm + "' for " + getClass(), cause);
		}
	}

	public boolean isMaskCritical() {
		return maskCritical;
	}

	public void setMaskCritical(boolean maskCritical) {
		this.maskCritical = maskCritical;
	}

}
