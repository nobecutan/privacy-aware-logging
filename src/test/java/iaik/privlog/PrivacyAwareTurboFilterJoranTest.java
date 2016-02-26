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

import java.net.URL;

import org.junit.Before;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.util.Loader;
import iaik.privlog.joran.PrivacyAwareJoranConfigurator;

public class PrivacyAwareTurboFilterJoranTest extends PrivacyAwareTurboFilterTest {

	@Override
	@Before
	public void before() {
		lc = new LoggerContext();
		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/configTurboFilter.xml");
			jc.doConfigure(configFile);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		root = lc.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		root.addAppender(getConsoleAppender(lc, rootMockOutputStream));

		logger = lc.getLogger(getClass());
		logger.addAppender(getConsoleAppender(lc, loggerMockOutputStream));
	}

}
