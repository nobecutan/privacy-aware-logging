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
package iaik.privlog;

import java.util.Collection;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.helpers.MessageFormatter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.LoggingEvent;
import iaik.privlog.sanitizers.IParamSanitizer;
import iaik.privlog.sanitizers.IParamSanitizerFactory;
import iaik.privlog.sanitizers.IdentitySanitizerFactory.IdentitySanitizer;

public class PrivacyAwareLoggingEvent extends LoggingEvent {

	public static class NonCriticalTag extends IdentitySanitizer {
		protected NonCriticalTag(Object parameter, int start, int startOriginal, int endOriginal) {
			super(null, parameter, start, startOriginal, endOriginal);
		}
	}

	protected static final Matcher TAG_MATCHER = Pattern.compile("(\\\\*)\\{([^{}]*)\\}").matcher("");

	public static PrivacyAwareLoggingEvent build(ParamSanitizerFactories sanitizers,
	                                             String fqcn,
	                                             Logger logger,
	                                             Level level,
	                                             String format,
	                                             Throwable throwable,
	                                             Object[] params)
	{
		ParamSanitizerList parameters = new ParamSanitizerList();
		StringBuilder newFormat = new StringBuilder();

		synchronized (TAG_MATCHER) {
			TAG_MATCHER.reset(format);

			int curParam = 0;
			int curPos = 0;
			int lengthPrevTags = 0;

			while (params != null && curParam < params.length && TAG_MATCHER.find()) {
				int numBackslash = TAG_MATCHER.group(1).length();
				String tagName = TAG_MATCHER.group(2);
				int start = TAG_MATCHER.start(2) - 1 - (numBackslash / 2);
				int end = TAG_MATCHER.end(2) + 1;

				if (numBackslash % 2 == 0) {
					// No backslash or an even number of backslashes
					Object param = params[curParam++];
					IParamSanitizer sanitizer = null;
					if (tagName.length() == 0) {
						sanitizer = new NonCriticalTag(param, start - lengthPrevTags, start, end - 1);
					} else {
						IParamSanitizerFactory sanitizerFactory = sanitizers.get(tagName);
						if (sanitizerFactory == null) {
							//Tagged as critical but no sanitizer configured
							// For the sake of privacy by default continue to next element
							continue;
						} else {
							sanitizer = sanitizerFactory.create(tagName, param, start - lengthPrevTags, start, end - 1);
						}
					}

					parameters.add(sanitizer);
					int s = start;
					if (numBackslash > 0) {
						s = start + numBackslash - numBackslash / 2;
					}
					newFormat.append(format.substring(curPos, s)).append("{}");
				} else {
					if (tagName.length() > 0) { // We have to handle these ourself
						newFormat.append(format.substring(curPos, start - 1)).append("{").append(tagName).append("}");
					} else {
						newFormat.append(format.substring(curPos, end));
					}
				}
				curPos = end;
				lengthPrevTags += tagName.length();
			}

			newFormat.append(format.substring(curPos));
		}
		return new PrivacyAwareLoggingEvent(fqcn, logger, level, newFormat.toString(), throwable, parameters, sanitizers);
	}

	protected final ParamSanitizerList parameters;
	protected final ParamSanitizerFactories sanitizers;
	protected transient String formattedSanitizedMessage;
	protected transient String formattedCriticalMessage;

	protected PrivacyAwareLoggingEvent(String fqcn,
	                                   Logger logger,
	                                   Level level,
	                                   String format,
	                                   Throwable throwable,
	                                   ParamSanitizerList parameters,
	                                   ParamSanitizerFactories sanitizers)
	{
		super(fqcn, logger, level, format, throwable, null);
		this.parameters = parameters;
		this.sanitizers = sanitizers;
	}

	@Override
	public String getFormattedMessage() {
		if (formattedSanitizedMessage == null) {
			Object[] argumentArray = parameters.getSanitized();
			if (argumentArray != null) {
				formattedSanitizedMessage = MessageFormatter.arrayFormat(getMessage(), argumentArray).getMessage();
			} else {
				formattedSanitizedMessage = getMessage();
			}
		}

		return formattedSanitizedMessage;
	}

	public String getFullyDisclosedFormattedMessage() {
		if (formattedCriticalMessage == null) {
			Object[] argumentArray = parameters.getCritical();
			if (argumentArray != null) {
				formattedCriticalMessage = MessageFormatter.arrayFormat(getMessage(), argumentArray).getMessage();
			} else {
				formattedCriticalMessage = getMessage();
			}
		}

		return formattedCriticalMessage;
	}

	public Collection<IParamSanitizer> getParameters() {
		return Collections.unmodifiableCollection(parameters);
	}

	public ParamSanitizerFactories getSanitizers() {
		return sanitizers;
	}
}
