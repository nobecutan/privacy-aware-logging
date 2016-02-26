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
package iaik.privlog.encoders;

import static org.mockito.Mockito.mock;

import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.CoreConstants;
import ch.qos.logback.core.FileAppender;
import ch.qos.logback.core.encoder.Encoder;
import iaik.privlog.ParamSanitizerFactories;
import iaik.privlog.PrivacyAwareAppender;
import iaik.privlog.helper.NonThrowingOutputStream;
import iaik.privlog.helper.TestUtils;
import iaik.privlog.layouts.DigestConverter;
import iaik.privlog.sanitizers.BlindingSanitizerFactory;
import iaik.security.provider.IAIK;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BdssTemplateEncoderTest {

	@BeforeClass
	public static void beforeClass() {
		IAIK.addAsProvider(true);
	}

	protected Logger root;
	protected LoggerContext lc;
	protected ParamSanitizerFactories sanitizers;
	protected NonThrowingOutputStream rootMockOutputStream = mock(NonThrowingOutputStream.class);

	@Before
	public void before() {
		lc = new LoggerContext();
		lc.setName("test context");

		@SuppressWarnings("unchecked")
		Map<String, String> ruleRegistry = (Map<String, String>) lc.getObject(CoreConstants.PATTERN_RULE_REGISTRY);
		if (ruleRegistry == null) {
			ruleRegistry = new HashMap<String, String>();
			lc.putObject(CoreConstants.PATTERN_RULE_REGISTRY, ruleRegistry);
		}
		ruleRegistry.put("digest", DigestConverter.class.getName());

		sanitizers = new ParamSanitizerFactories();
		sanitizers.put("Password", new BlindingSanitizerFactory());
		sanitizers.put("blind", new BlindingSanitizerFactory());
		sanitizers.put("anon", new BlindingSanitizerFactory());

		PrivacyAwareAppender paAppender = new PrivacyAwareAppender();
		paAppender.setContext(lc);
		paAppender.setSanitizerFactories(sanitizers);
		paAppender.addAppender(getConsoleAppender(lc, System.out));
		paAppender.addAppender(getFileAppender(lc));
		paAppender.start();

		root = lc.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		root.addAppender(paAppender);
	}

	protected static Appender<ILoggingEvent> getFileAppender(LoggerContext lc) {
		FileAppender<ILoggingEvent> fileAppender = new FileAppender<ILoggingEvent>();
		fileAppender.setContext(lc);
		fileAppender.setAppend(false);
		fileAppender.setFile("/tmp/testBdssTemplates.log");
		fileAppender.setEncoder(getEncoder(lc, false));
		fileAppender.start();
		return fileAppender;
	}

	protected static Appender<ILoggingEvent> getConsoleAppender(LoggerContext lc, OutputStream os) {
		ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<>();
		consoleAppender.setContext(lc);
		consoleAppender.setEncoder(getEncoder(lc, false));
		consoleAppender.start();
		consoleAppender.setOutputStream(os);
		return consoleAppender;
	}

	protected static Encoder<ILoggingEvent> getEncoder(LoggerContext lc, boolean encrypt) {

		BdssTemplateEncoder bdssEncoder = new BdssTemplateEncoder();
		bdssEncoder.setContext(lc);
		bdssEncoder.setPublicParametersCertificate(TestUtils.getBdssPublicParameterCert());
		bdssEncoder.setOriginatorKeyAndCertificate(TestUtils.getOriginatorKeyAndCertificate());
		bdssEncoder.setProxyCertificate(TestUtils.getProxyCert());
		bdssEncoder.setPattern("%relative%digest(%level%msg){base64=true,algorithm=sha256}");
		bdssEncoder.start();

		if (encrypt) {
			CmsWrappingEncryptionEncoder encoder = new CmsWrappingEncryptionEncoder();
			encoder.setBaseEncoder(bdssEncoder);
			encoder.setAlgorithm("AES/CBC/PKCS5Padding");
			encoder.addRecipient(TestUtils.getOriginatorKeyAndCertificate().getCertificateChain()[0]);
			return encoder;
		} else {
			@SuppressWarnings("unchecked")
			Encoder<ILoggingEvent> cast = Encoder.class.cast(bdssEncoder);
			return cast;
		}
	}

	@After
	public void after() {
		lc.stop();
	}

	@Test
	public void testBasic() {

		for (int i = 0; i < 10; ++i) {
			root.info("Hello {blind} World", "Invocation: " + (i + 1));
		}
		root.debug("Hello World", new RuntimeException("Something has gone bad."));
	}

}
