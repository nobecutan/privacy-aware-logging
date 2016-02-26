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

import static org.mockito.Mockito.mock;

import java.io.OutputStream;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.FileAppender;
import ch.qos.logback.core.status.OnConsoleStatusListener;
import iaik.privlog.encoders.PrivacyAwarePatternLayoutEncoder;
import iaik.privlog.helper.NonThrowingOutputStream;
import iaik.privlog.sanitizers.BlindingSanitizerFactory;
import iaik.security.provider.IAIK;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class DigestConverterTest {

	@BeforeClass
	public static void beforeClass() {
		IAIK.addAsProvider(true);
	}

	protected Logger logger;
	protected Logger root;
	protected LoggerContext lc;
	protected ParamSanitizerFactories sanitizers;
	protected NonThrowingOutputStream loggerMockOutputStream = mock(NonThrowingOutputStream.class);
	protected NonThrowingOutputStream rootMockOutputStream = mock(NonThrowingOutputStream.class);

	@Before
	public void before() {
		lc = new LoggerContext();
		lc.setName("test context");
		OnConsoleStatusListener.addNewInstanceToContext(lc);

		sanitizers = new ParamSanitizerFactories();
		sanitizers.put("Password", new BlindingSanitizerFactory());
		sanitizers.put("blind", new BlindingSanitizerFactory());
		sanitizers.put("anon", new BlindingSanitizerFactory());

		root = lc.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		root.addAppender(getConsoleAppender(lc, System.out));

		FileAppender<ILoggingEvent> fileAppender = new FileAppender<ILoggingEvent>();
		fileAppender.setContext(lc);
		fileAppender.setAppend(false);
		fileAppender.setFile("/tmp/testDigestConverter.log");
		fileAppender.setEncoder(getEncoder(lc));
		fileAppender.start();

		root.addAppender(fileAppender);
	}

	protected static Appender<ILoggingEvent> getConsoleAppender(LoggerContext lc, OutputStream os) {
		ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<ILoggingEvent>();
		consoleAppender.setContext(lc);
		consoleAppender.setEncoder(getEncoder(lc));
		consoleAppender.start();
		consoleAppender.setOutputStream(os);
		return consoleAppender;
	}

	protected static PatternLayoutEncoder getEncoder(LoggerContext lc) {
		PatternLayoutEncoder layoutEncoder = new PrivacyAwarePatternLayoutEncoder();
		layoutEncoder.setPattern(
		    "%-4relative %digest(%-5level - %msg){file=/tmp/testDigestConverter.log,base64=true,algorithm=sha512} %n");
		layoutEncoder.setContext(lc);
		layoutEncoder.setOutputPatternAsHeader(true);
		layoutEncoder.start();
		return layoutEncoder;
	}

	@Test
	public void testBasic() {
		for (int i = 0; i < 10000; ++i) {
			root.info("Hello World");
		}
		root.debug("Hello World");
	}
}
