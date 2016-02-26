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

import java.util.Collections;
import java.util.Iterator;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.AppenderBase;
import ch.qos.logback.core.spi.AppenderAttachable;
import ch.qos.logback.core.spi.AppenderAttachableImpl;
import iaik.privlog.sanitizers.IParamSanitizerFactory;

public class PrivacyAwareAppender extends AppenderBase<ILoggingEvent>
    implements AppenderAttachable<ILoggingEvent>, IParamSanitizerFactoriesAware
{
	/**
	 * The fully qualified name of this class. Used in gathering caller
	 * information.
	 */
	public static final String FQCN = PrivacyAwareAppender.class.getName();

	private AppenderAttachableImpl<ILoggingEvent> aai;

	protected ParamSanitizerFactories sanitizers;

	@Override
	public void setSanitizerFactories(ParamSanitizerFactories sanitizers) {
		this.sanitizers = sanitizers;
	}

	@Override
	public void addSanitizerFactory(String tagName, IParamSanitizerFactory sanitizerFactory) {
		if (sanitizers == null) {
			sanitizers = new ParamSanitizerFactories();
		}
		sanitizers.put(tagName, sanitizerFactory);
	}

	@Override
	protected void append(ILoggingEvent eventObject) {

		if (!isStarted()) {
			addError("The appender " + getClass().getName() + " has not been started.");
			return;
		}

		Logger logger = ((LoggerContext) getContext()).getLogger(eventObject.getLoggerName());

		LoggingEvent event = PrivacyAwareLoggingEvent.build(sanitizers, FQCN, logger, eventObject.getLevel(),
		    eventObject.getMessage(), null, eventObject.getArgumentArray());
		event.setMarker(eventObject.getMarker());
		event.setThrowableProxy((ThrowableProxy) eventObject.getThrowableProxy());

		appendLoopOnAppenders(event);
	}

	@Override
	public void start() {
		if (this.sanitizers == null) {
			addWarn("The filter " + getClass().getName() + " should be configured with a ParamSanitizers instance.");
			this.sanitizers = new ParamSanitizerFactories();
		}

		super.start();
	}

	/**
	 * Remove all previously added appenders from this logger instance.
	 * <p/>
	 * This is useful when re-reading configuration information.
	 */
	@Override
	public void detachAndStopAllAppenders() {
		if (aai != null) {
			aai.detachAndStopAllAppenders();
		}
	}

	@Override
	public boolean detachAppender(String name) {
		if (aai == null) {
			return false;
		}
		return aai.detachAppender(name);
	}

	// this method MUST be synchronized. See comments on 'aai' field for further
	// details.
	@Override
	public synchronized void addAppender(Appender<ILoggingEvent> newAppender) {
		if (aai == null) {
			aai = new AppenderAttachableImpl<ILoggingEvent>();
		}
		aai.addAppender(newAppender);
	}

	@Override
	public boolean isAttached(Appender<ILoggingEvent> appender) {
		if (aai == null) {
			return false;
		}
		return aai.isAttached(appender);
	}

	@Override
	@SuppressWarnings("unchecked")
	public Iterator<Appender<ILoggingEvent>> iteratorForAppenders() {
		if (aai == null) {
			return Collections.EMPTY_LIST.iterator();
		}
		return aai.iteratorForAppenders();
	}

	@Override
	public Appender<ILoggingEvent> getAppender(String name) {
		if (aai == null) {
			return null;
		}
		return aai.getAppender(name);
	}

	protected int appendLoopOnAppenders(ILoggingEvent event) {
		if (aai != null) {
			return aai.appendLoopOnAppenders(event);
		} else {
			return 0;
		}
	}

	/**
	 * Remove the appender passed as parameter form the list of appenders.
	 */
	@Override
	public boolean detachAppender(Appender<ILoggingEvent> appender) {
		if (aai == null) {
			return false;
		}
		return aai.detachAppender(appender);
	}

}
