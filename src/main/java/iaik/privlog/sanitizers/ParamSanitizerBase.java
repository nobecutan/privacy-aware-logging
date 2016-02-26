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

import org.slf4j.helpers.MessageFormatter;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public abstract class ParamSanitizerBase implements IParamSanitizer {

	protected static final String PARAM_ONLY_MESSAGE_PATTERN = "{}";

	protected String tagName;
	protected Object parameter;
	protected String critical;
	protected String sanitized;
	protected Boolean equal;
	protected int start;
	protected int startOriginal;
	protected int endOriginal;

	protected ParamSanitizerBase(String tagName, Object parameter, int start, int startOriginal, int endOriginal) {
		this.tagName = tagName;
		this.parameter = parameter;
		this.start = start;
		this.startOriginal = startOriginal;
		this.endOriginal = endOriginal;
	}

	@Override
	public String getCritical() {
		if (critical == null) {
			critical = MessageFormatter.format(PARAM_ONLY_MESSAGE_PATTERN, parameter).getMessage();
		}
		return critical;
	}

	@Override
	public boolean isCriticalAndSanitizedEqual() {
		if (equal == null) {
			equal = getCritical().equals(getSanitized());
		}
		return equal;
	}

	@Override
	public int getStart() {
		return start;
	}

	@Override
	public int getStartOriginal() {
		return startOriginal;
	}

	@Override
	public int getEndOriginal() {
		return endOriginal;
	}

}
