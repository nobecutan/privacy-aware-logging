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

import org.slf4j.Marker;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.EventArgUtil;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.spi.TurboFilterList;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;
import iaik.privlog.sanitizers.IParamSanitizerFactory;

public class PrivacyAwareTurboFilter extends TurboFilter implements IParamSanitizerFactoriesAware {
	private static final String FQCN = PrivacyAwareTurboFilter.class.getName();

	private final TurboFilterList turboFilterList = new TurboFilterList();
	protected ParamSanitizerFactories sanitizers;

	public PrivacyAwareTurboFilter() {
	}

	public PrivacyAwareTurboFilter(ParamSanitizerFactories sanitizers) {
		this.sanitizers = sanitizers;
		start();
	}

	@Override
	public void addSanitizerFactory(String tagName, IParamSanitizerFactory sanitizerFactory) {
		if (sanitizers == null) {
			sanitizers = new ParamSanitizerFactories();
		}

		sanitizers.put(tagName, sanitizerFactory);
	}

	@Override
	public void setSanitizerFactories(ParamSanitizerFactories sanitizers) {
		this.sanitizers = sanitizers;
	}

	public TurboFilterList getTurboFilterList() {
		return turboFilterList;
	}

	public void addTurboFilter(TurboFilter newFilter) {
		turboFilterList.add(newFilter);
	}

	/**
	 * First processPriorToRemoval all registered turbo filters and then clear the
	 * registration list.
	 */
	public void resetTurboFilterList() {
		for (TurboFilter tf : turboFilterList) {
			tf.stop();
		}
		turboFilterList.clear();
	}

	final FilterReply getTurboFilterChainDecision(final Marker marker,
	                                              final Logger logger,
	                                              final Level level,
	                                              final String format,
	                                              final Object[] params,
	                                              final Throwable t)
	{
		if (turboFilterList.size() == 0) {
			return FilterReply.NEUTRAL;
		}
		return turboFilterList.getTurboFilterChainDecision(marker, logger, level, format, params, t);
	}

	@Override
	public FilterReply decide(Marker marker,
	                          Logger logger,
	                          Level level,
	                          String format,
	                          Object[] argArray,
	                          Throwable throwable)
	{
		if (!isStarted()) {
			addError("The filter " + getClass().getName() + " has not been started.");
			return FilterReply.NEUTRAL;
		}

		if (format == null) {
			return FilterReply.NEUTRAL;
		}

		final FilterReply decision = getTurboFilterChainDecision(marker, logger, level, format, argArray, throwable);

		if (decision == FilterReply.NEUTRAL) {
			if (logger.getEffectiveLevel().levelInt > level.levelInt) {
				return FilterReply.DENY;
			}
		} else if (decision == FilterReply.DENY) {
			return FilterReply.DENY;
		}

		Throwable t = throwable;
		Object[] params = argArray;
		if (throwable == null) {
			t = EventArgUtil.extractThrowable(params);
			if (EventArgUtil.successfulExtraction(t)) {
				params = EventArgUtil.trimmedCopy(argArray);
			}
		}

		//Call appenders with sanitized data
		LoggingEvent event = PrivacyAwareLoggingEvent.build(sanitizers, FQCN, logger, level, format, t, params);
		event.setMarker(marker);
		logger.callAppenders(event);

		// Do not further process the original log entry
		return FilterReply.DENY;
	}

	@Override
	public void start() {
		if (this.sanitizers == null) {
			addWarn("The filter " + getClass().getName() + " should be configured with a ParamSanitizers instance.");
			this.sanitizers = new ParamSanitizerFactories();
		}

		super.start();
	}

}
