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
package iaik.privlog.layouts;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.input.ReversedLinesFileReader;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.pattern.CompositeConverter;
import ch.qos.logback.core.util.CloseUtil;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class DigestConverter extends CompositeConverter<ILoggingEvent> {

	protected static final String NOT_STARTED_MESSAGE = "ERROR_DigestConverter_not_started";

	protected String algorithm = "SHA1";
	protected boolean base64 = false;
	protected boolean chained = true;
	protected Charset charset = Charset.forName("utf-8");
	protected String file = null;
	protected String prefix = " [digest:";
	protected String suffix = "]";

	protected MessageDigest digest;
	protected byte[] prevHash;

	protected String createDigest(String in) {
		synchronized (digest) {
			if (chained) {
				digest.update(prevHash);
			}
			prevHash = digest.digest(in.getBytes(charset));
			String prevHashString = base64 ? Base64.encodeBase64String(prevHash) : Hex.encodeHexString(prevHash);
			return prevHashString;
		}
	}

	@Override
	protected String transform(ILoggingEvent event, String in) {
		StringBuilder buf = new StringBuilder(in);

		buf.append(prefix);
		buf.append(started ? createDigest(in) : NOT_STARTED_MESSAGE);
		buf.append(suffix);

		return buf.toString();
	}

	@Override
	public void start() {
		if (!processOptions()) {
			return;
		}

		if (file != null) {
			try {
				File logFile = new File(file);
				if (logFile.canRead()) {
					ReversedLinesFileReader reader = null;
					try {
						reader = new ReversedLinesFileReader(logFile);
						String lastLine = reader.readLine();
						if (lastLine != null) {
							StringBuilder pattern = new StringBuilder();
							pattern.append(Pattern.quote(prefix));
							pattern.append(base64 ? "([0-9a-zA-Z+/=]+)" : "([0-9a-z]+)");
							pattern.append(Pattern.quote(suffix));

							Matcher m = Pattern.compile(pattern.toString()).matcher(lastLine);
							if (m.find()) {
								String hash = m.group(1);
								if (!NOT_STARTED_MESSAGE.equals(hash)) {
									try {
										prevHash = base64 ? Base64.decodeBase64(hash) : Hex.decodeHex(hash.toCharArray());
									} catch (Exception cause) {
										addError("Failed to decode last digest value [" + hash + "]", cause);
										return;
									}
								}
							} else {
								addWarn("Failed to find digest in last entry of log file [" + file + "]");
							}
						}
					} finally {
						CloseUtil.closeQuietly(reader);
					}
				} else {
					addWarn("Failed to read log file [" + file + "]");
				}
			} catch (IOException cause) {
				addError("Failed to read log file [" + file + "]", cause);
				return;
			}

		}

		try {
			digest = MessageDigest.getInstance(algorithm);
			if (prevHash == null) {
				synchronized (digest) {
					prevHash = digest.digest();
				}
			}
		} catch (NoSuchAlgorithmException cause) {
			addError("Message digest algorithm [" + algorithm + "] not found.", cause);
			return;
		}
		super.start();
	}

	protected boolean processOptions() {
		List<String> options = getOptionList();
		if (options == null) {
			return true;
		}

		for (String option : options) {
			try {
				String[] keyVal = option.split("=", 2);
				if (keyVal.length != 2) {
					continue;
				}

				switch (keyVal[0]) {
				case "algorithm":
					algorithm = keyVal[1];
					break;

				case "base64":
					base64 = Boolean.valueOf(keyVal[1]);
					break;

				case "chained":
					chained = Boolean.valueOf(keyVal[1]);
					break;

				case "charset":
					charset = Charset.forName(keyVal[1]);
					break;

				case "file":
					file = keyVal[1];
					break;

				case "prefix":
					prefix = keyVal[1];
					break;

				case "suffix":
					suffix = keyVal[1];
					break;
				}
			} catch (Exception cause) {
				addError("Failed to handle option [" + option + "]", cause);
				return false;
			}
		}
		return true;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public void setBase64(boolean base64) {
		this.base64 = base64;
	}

	public void setChained(boolean chained) {
		this.chained = chained;
	}

	public void setCharset(Charset charset) {
		this.charset = charset;
	}

	public void setFile(String file) {
		this.file = file;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	public void setSuffix(String suffix) {
		this.suffix = suffix;
	}

}
