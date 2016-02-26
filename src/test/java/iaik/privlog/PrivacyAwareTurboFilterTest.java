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

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

import java.io.OutputStream;

import org.hamcrest.Description;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;
import iaik.privlog.helper.NonThrowingOutputStream;
import iaik.privlog.sanitizers.AnonymizingSanitizerFactory;
import iaik.privlog.sanitizers.BlindingSanitizerFactory;
import iaik.security.provider.IAIK;

public class PrivacyAwareTurboFilterTest {

	@BeforeClass
	public static void beforeClass() {
		IAIK.addAsProvider(true);
	}

	protected Logger logger;
	protected Logger root;
	protected LoggerContext lc;
	protected ParamSanitizerFactories sanitizers;
	protected NonThrowingOutputStream loggerMockOutputStream;
	protected NonThrowingOutputStream rootMockOutputStream;
	
  public PrivacyAwareTurboFilterTest() {
  	loggerMockOutputStream = mock(NonThrowingOutputStream.class);
  	rootMockOutputStream = mock(NonThrowingOutputStream.class);

		Mockito.doAnswer(new Answer<Void>() {

			@Override
			public Void answer(InvocationOnMock invocation)
			    throws Throwable
			{
				System.err.write(invocation.getArgumentAt(0, byte[].class));
				return null;
			}
		}).when(rootMockOutputStream).write(any(byte[].class));

		Mockito.doAnswer(new Answer<Void>() {

			@Override
			public Void answer(InvocationOnMock invocation)
			    throws Throwable
			{
				System.out.write(invocation.getArgumentAt(0, byte[].class));
				return null;
			}
		}).when(loggerMockOutputStream).write(any(byte[].class));
  }

	@Before
	public void before() {
		setUpCommon();

		PrivacyAwareTurboFilter paFilter = new PrivacyAwareTurboFilter();
		paFilter.setContext(lc);
		paFilter.setSanitizerFactories(sanitizers);
		paFilter.start();

		lc.addTurboFilter(paFilter);

		logger = lc.getLogger(getClass());
		logger.addAppender(getConsoleAppender(lc, loggerMockOutputStream));
		logger.setAdditive(false);
	}

	protected void setUpCommon() {
		lc = new LoggerContext();
		lc.setName("test context");

		sanitizers = new ParamSanitizerFactories();
		sanitizers.put("Password", new BlindingSanitizerFactory());
		sanitizers.put("blind", new BlindingSanitizerFactory());
		sanitizers.put("anon", new AnonymizingSanitizerFactory());

		root = lc.getLogger(Logger.ROOT_LOGGER_NAME);
		root.addAppender(getConsoleAppender(lc, rootMockOutputStream));
	}

	protected static Appender<ILoggingEvent> getConsoleAppender(LoggerContext lc, OutputStream os) {
		PatternLayoutEncoder layoutEncoder = new PatternLayoutEncoder();
		layoutEncoder.setPattern("%-4relative %-5level - %msg%n");
		layoutEncoder.setContext(lc);
		layoutEncoder.start();

		ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<ILoggingEvent>();
		consoleAppender.setContext(lc);
		consoleAppender.setEncoder(layoutEncoder);
		consoleAppender.start();
		consoleAppender.setOutputStream(os);
		return consoleAppender;
	}

	protected byte[] getMsgEqualsMatcher(final String target) {
		return argThat(new ArgumentMatcher<byte[]>() {

			@Override
			public boolean matches(final Object argument) {
				byte[] b = (byte[]) argument;
				return new String(b).split(" - ", 2)[1].equals(target + "\n");
			}

			@Override
			public void describeTo(Description description) {
				description.appendText("equals(\"" + target + "\")");
			}
		});
	}

	protected byte[] getMsgStartsWithMatcher(final String target) {
		return argThat(new ArgumentMatcher<byte[]>() {

			@Override
			public boolean matches(final Object argument) {
				return new String((byte[]) argument).split(" - ", 2)[1].startsWith(target);
			}

			@Override
			public void describeTo(Description description) {
				description.appendText("startsWith(\"" + target + "\")");
			}
		});
	}

	@Test
	public void testBasic() {
		LoggerContext basicContext = new LoggerContext();
		basicContext.setName("basic context");
		Logger root = basicContext.getLogger(Logger.ROOT_LOGGER_NAME);
		root.addAppender(getConsoleAppender(basicContext, rootMockOutputStream));

		root.debug("Hey this is the {} I want to see", "message");
		verify(rootMockOutputStream).write(getMsgEqualsMatcher("Hey this is the message I want to see"));

		root.debug("Hey this is the {Password} I want to see", "message");
		verify(rootMockOutputStream).write(getMsgEqualsMatcher("Hey this is the {Password} I want to see"));
	}

	@Test
	/**
	 * @PreCondition: 
	 */
	public void testPrivacyByDesign() {
		LoggerContext basicContext = new LoggerContext();
		basicContext.setName("basic context");
		Logger root = basicContext.getLogger(Logger.ROOT_LOGGER_NAME);
		root.addAppender(getConsoleAppender(lc, System.out));
		root.addAppender(getConsoleAppender(basicContext, rootMockOutputStream));

		root.debug("Username: {Username}, Password: {Password}", "username", "password");
		verify(rootMockOutputStream).write(getMsgEqualsMatcher("Username: {Username}, Password: {Password}"));

		root.debug("Username: {}, Password: {Password}", "username", "password");
		verify(rootMockOutputStream).write(getMsgEqualsMatcher("Username: username, Password: {Password}"));
	}

	@Test
	public void testBlinding() {
		logger.debug("Blinded {blind}", "message");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Blinded " + BlindingSanitizerFactory.BLINDING_MASK));

		logger.debug("Password: {blind}, Username: {}", "password", "username");
		verify(loggerMockOutputStream).write(
		    getMsgEqualsMatcher("Password: " + BlindingSanitizerFactory.BLINDING_MASK + ", Username: username"));
	}

	@Test
	public void testAnonymizing() {
		logger.debug("Anonymized {anon}", "message");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Anonymized [anon]"));
	}

	@Test
	public void testEscapeCharBasic() {
		logger.info("Hello {}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World"));
		verify(rootMockOutputStream, never()).write(any(byte[].class));

		logger.info("Hello \\{}{}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello {}World"));

		logger.info("Hello \\\\{}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello \\World"));

//		logger.info("Hello \\\\\\{}{}", "World");
//		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello \\{}World"));
//
//		logger.info("Hello \\\\\\\\{}", "World");
//		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello \\\\World"));
//
//		logger.info("Hello \\\\\\\\\\{}", "World");
//		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello \\\\{}"));

		logger.info("Hello \\{} my {}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello {} my World"));

	}

	@Test
	public void testEscapeCharPrivacyAware() {
		logger.info("Hello {blind}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello " + BlindingSanitizerFactory.BLINDING_MASK));
		verify(rootMockOutputStream, never()).write(any(byte[].class));

		logger.info("Hello \\{blind}{}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello {blind}World"));

		logger.info("Hello \\\\{blind}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello \\" + BlindingSanitizerFactory.BLINDING_MASK));

		logger.info("Hello \\\\\\{blind}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello \\{blind}"));

		logger.info("Hello \\{blind} {}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello {blind} World"));

		logger.info("Hello \\{} {blind}", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello {} " + BlindingSanitizerFactory.BLINDING_MASK));

		logger.info("Hello \\{blind} {blind}", "World");
		verify(loggerMockOutputStream)
		    .write(getMsgEqualsMatcher("Hello {blind} " + BlindingSanitizerFactory.BLINDING_MASK));

	}

	@Test
	public void testAdditivity() {
		logger.setAdditive(true);

		logger.warn("Hello {} Additivity", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Additivity"));
		verify(rootMockOutputStream).write(getMsgEqualsMatcher("Hello World Additivity"));

		logger.warn("Hello {blind} Additivity", "World");
		verify(loggerMockOutputStream).write(
		    getMsgEqualsMatcher("Hello " + BlindingSanitizerFactory.BLINDING_MASK + " Additivity"));
		verify(rootMockOutputStream).write(
		    getMsgEqualsMatcher("Hello " + BlindingSanitizerFactory.BLINDING_MASK + " Additivity"));
	}

	@Test
	public void testPositionBasic() {
		logger.warn("{} World Position", "Hello");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Position"));

		reset(loggerMockOutputStream);
		logger.warn("Hello {} Position", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Position"));

		reset(loggerMockOutputStream);
		logger.warn("Hello World {}", "Position");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Position"));

		reset(loggerMockOutputStream);
		logger.warn("{} World {}", "Hello", "Position");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Position"));

		reset(loggerMockOutputStream);
		logger.warn("{} {} {}", new Object[] { "Hello", "World", "Position" });
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Position"));

		reset(loggerMockOutputStream);
		logger.warn("{} {} {}");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("{} {} {}"));

		reset(loggerMockOutputStream);
		logger.warn("{} {} {}", "Hello", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World {}"));

		reset(loggerMockOutputStream);
		logger.warn("Hello World Position");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Position"));

		reset(loggerMockOutputStream);
		logger.warn("Hello World Position", new Object[] { "Hello", "World", "Position" });
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Position"));
	}

	@Test
	public void testPositionPrivacy() {
		logger.warn("{blind} World Position", "Hello");
		verify(loggerMockOutputStream).write(
		    getMsgEqualsMatcher(BlindingSanitizerFactory.BLINDING_MASK + " World Position"));

		reset(loggerMockOutputStream);
		logger.warn("Hello {anon} Position", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello [anon] Position"));

		reset(loggerMockOutputStream);
		logger.warn("Hello World {blind}", "Position");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World " + BlindingSanitizerFactory.BLINDING_MASK));

		reset(loggerMockOutputStream);
		logger.warn("{anon} World {blind}", "Hello", "Position");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("[anon] World " + BlindingSanitizerFactory.BLINDING_MASK));

		reset(loggerMockOutputStream);
		logger.warn("{anon} {blind} {}", new Object[] { "Hello", "World", "Position" });
		verify(loggerMockOutputStream).write(
		    getMsgEqualsMatcher("[anon] " + BlindingSanitizerFactory.BLINDING_MASK + " Position"));

		reset(loggerMockOutputStream);
		logger.warn("{blind} {anon} {}");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("{blind} {anon} {}"));

		reset(loggerMockOutputStream);
		logger.warn("{} {blind} {anon}", "Hello", "World");
		verify(loggerMockOutputStream).write(
		    getMsgEqualsMatcher("Hello " + BlindingSanitizerFactory.BLINDING_MASK + " {anon}"));
	}

	@Test
	public void testThrowableBasic() {
		RuntimeException cause = new RuntimeException("Test RuntimeException");

		logger.info("{} World Throwable", "Hello", cause);
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher("Hello World Throwable\njava.lang.RuntimeException: Test RuntimeException"));

		reset(loggerMockOutputStream);
		logger.info("{} World Throwable", cause);
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher("{} World Throwable\njava.lang.RuntimeException: Test RuntimeException"));

		reset(loggerMockOutputStream);
		logger.info("Hello World Throwable", "Param1", cause);
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher("Hello World Throwable\njava.lang.RuntimeException: Test RuntimeException"));

		reset(loggerMockOutputStream);
		logger.info("{} {} Throwable", new Object[] { "Hello", "World", cause });
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher("Hello World Throwable\njava.lang.RuntimeException: Test RuntimeException"));
	}

	@Test
	public void testThrowablePrivacyAware() {
		RuntimeException cause = new RuntimeException("Test RuntimeException");

		logger.info("{blind} World Throwable", "Hello", cause);
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher(BlindingSanitizerFactory.BLINDING_MASK
		        + " World Throwable\njava.lang.RuntimeException: Test RuntimeException"));

		reset(loggerMockOutputStream);
		logger.info("{anon} World Throwable", cause);
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher("{anon} World Throwable\njava.lang.RuntimeException: Test RuntimeException"));

		reset(loggerMockOutputStream);
		logger.info("Hello World Throwable", "Param1", cause);
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher("Hello World Throwable\njava.lang.RuntimeException: Test RuntimeException"));

		reset(loggerMockOutputStream);
		logger.info("{blind} {anon} Throwable", new Object[] { "Hello", "World", cause });
		verify(loggerMockOutputStream).write(
		    getMsgStartsWithMatcher(BlindingSanitizerFactory.BLINDING_MASK
		        + " [anon] Throwable\njava.lang.RuntimeException: Test RuntimeException"));
	}
}
