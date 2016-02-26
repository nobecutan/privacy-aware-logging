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

import org.apache.commons.codec.binary.Base64;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public abstract class ParamEncryptingSanitizerBase extends ParamSanitizerBase {
	protected Base64 base64 = new Base64();
	protected final String identifier;
	protected String critical;
	protected final boolean showSequenceNumber;
	protected long sequenceNumber = 0;

	protected ParamEncryptingSanitizerBase(String tagName,
	                                       Object parameter,
	                                       int start,
	                                       int startOriginal,
	                                       int endOriginal,
	                                       String identifier,
	                                       boolean showSequenceNumber)
	{
		super(tagName, parameter, start, startOriginal, endOriginal);
		this.identifier = identifier;
		this.showSequenceNumber = showSequenceNumber;
	}

	protected abstract byte[] getCipherText();

	@Override
	public final String getSanitized() {
		if (sanitized == null) {
			StringBuilder sb = new StringBuilder();
			sb.append("{").append(identifier).append(":");
			synchronized (base64) {
				if (showSequenceNumber) {
					sb.append(sequenceNumber).append(":");
				}
				sb.append(base64.encodeToString(getCipherText()));
				++sequenceNumber;
			}
			sb.append("}");
			sanitized = sb.toString();
		}
		return sanitized;
	}

}
