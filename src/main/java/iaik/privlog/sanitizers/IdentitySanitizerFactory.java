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

import org.slf4j.helpers.Util;

import ch.qos.logback.core.spi.ContextAwareBase;
import ch.qos.logback.core.spi.LifeCycle;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class IdentitySanitizerFactory extends ContextAwareBase implements IParamSanitizerFactory, LifeCycle {

	public static class IdentitySanitizer extends ParamSanitizerBase {

		protected IdentitySanitizer(String tagName, Object parameter, int start, int startOriginal, int endOriginal) {
			super(tagName, parameter, start, startOriginal, endOriginal);
			equal = true;
		}

		@Override
		public String getSanitized() {
			if (sanitized == null) {
				sanitized = getCritical();
			}
			return sanitized;
		}

	}

	protected boolean started;

	@Override
	public IdentitySanitizer create(String tagName, Object parameter, int start, int startOriginal, int endOriginal) {
		if (!isStarted()) {
			addError("The identity sanitizer factory has not been started.");
			return new IdentitySanitizer(tagName, "{" + tagName + "}", start, startOriginal, endOriginal);
		}
		return new IdentitySanitizer(tagName, parameter, start, startOriginal, endOriginal);
	}

	@Override
	public void start() {
		if (context == null) {
			Util.report("IdentitySanitizer cannot be started w/o a context");
			throw new RuntimeException("IdentitySanitizer cannot be started w/o a context");
		}

		addWarn("=========================\n||       WARNING       ||\n=========================\n\n"
		    + "The IdentitySanitizer does NOT sanitize at all!");

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
