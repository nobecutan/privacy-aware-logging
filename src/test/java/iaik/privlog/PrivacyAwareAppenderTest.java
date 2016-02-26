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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

import org.junit.Before;
import org.junit.Test;

import iaik.privlog.sanitizers.BlindingSanitizerFactory;

public class PrivacyAwareAppenderTest extends PrivacyAwareTurboFilterTest {

	@Override
	@Before
	public void before() {
		setUpCommon();

		PrivacyAwareAppender paAppender = new PrivacyAwareAppender();
		paAppender.setContext(lc);
		paAppender.setSanitizerFactories(sanitizers);
		paAppender.addAppender(getConsoleAppender(lc, System.out));
		paAppender.addAppender(getConsoleAppender(lc, loggerMockOutputStream));
		paAppender.start();

		logger = lc.getLogger(getClass());
		logger.addAppender(paAppender);
		logger.setAdditive(false);
	}

	@Override
	@Test
	public void testAdditivity() {
		logger.warn("Hello {} Additivity", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Additivity"));
		verify(rootMockOutputStream, never()).write(any(byte[].class));

		reset(loggerMockOutputStream);
		reset(rootMockOutputStream);
		logger.warn("Hello {blind} Additivity", "World");
		verify(loggerMockOutputStream)
		    .write(getMsgEqualsMatcher("Hello " + BlindingSanitizerFactory.BLINDING_MASK + " Additivity"));
		verify(rootMockOutputStream, never()).write(any(byte[].class));

		logger.setAdditive(true);

		reset(loggerMockOutputStream);
		reset(rootMockOutputStream);
		logger.warn("Hello {} Additivity", "World");
		verify(loggerMockOutputStream).write(getMsgEqualsMatcher("Hello World Additivity"));
		verify(rootMockOutputStream).write(getMsgEqualsMatcher("Hello World Additivity"));

		reset(loggerMockOutputStream);
		reset(rootMockOutputStream);
		logger.warn("Hello {blind} Additivity", "World");
		verify(loggerMockOutputStream)
		    .write(getMsgEqualsMatcher("Hello " + BlindingSanitizerFactory.BLINDING_MASK + " Additivity"));
		verify(rootMockOutputStream).write(getMsgEqualsMatcher("Hello {blind} Additivity"));
	}
}
