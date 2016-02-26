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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.CoreConstants;
import ch.qos.logback.core.FileAppender;
import ch.qos.logback.core.encoder.Encoder;
import ch.qos.logback.core.status.OnConsoleStatusListener;
import ch.qos.logback.core.util.CloseUtil;
import iaik.cms.EnvelopedDataStream;
import iaik.privlog.helper.NonThrowingOutputStream;
import iaik.privlog.helper.TestUtils;
import iaik.privlog.layouts.DigestConverter;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CmsEncryptionEncoderTest {

	@BeforeClass
	public static void beforeClass() {
		IAIK.addAsProvider(true);
	}

	protected Logger root;
	protected LoggerContext lc;
	protected NonThrowingOutputStream rootMockOutputStream = mock(NonThrowingOutputStream.class);

	@Before
	public void before() {
		lc = new LoggerContext();
		lc.setName("test context");
		OnConsoleStatusListener.addNewInstanceToContext(lc);

		@SuppressWarnings("unchecked")
		Map<String, String> ruleRegistry = (Map<String, String>) lc.getObject(CoreConstants.PATTERN_RULE_REGISTRY);
		if (ruleRegistry == null) {
			ruleRegistry = new HashMap<String, String>();
			lc.putObject(CoreConstants.PATTERN_RULE_REGISTRY, ruleRegistry);
		}
		ruleRegistry.put("digest", DigestConverter.class.getName());

		root = lc.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		root.addAppender(getConsoleAppender(lc, System.out));
	}

	protected static Appender<ILoggingEvent> getFileAppender(LoggerContext lc) {
		FileAppender<ILoggingEvent> fileAppender = new FileAppender<ILoggingEvent>();
		fileAppender.setContext(lc);
		fileAppender.setAppend(false);
		fileAppender.setFile("/tmp/testCmsEncWrappingEncoder.log");
		fileAppender.setEncoder(getEncoder(lc, true));
		fileAppender.start();
		return fileAppender;
	}

	protected static Appender<ILoggingEvent> getConsoleAppender(LoggerContext lc, OutputStream os) {
		ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<ILoggingEvent>();
		consoleAppender.setContext(lc);
		consoleAppender.setEncoder(getEncoder(lc, false));
		consoleAppender.start();
		consoleAppender.setOutputStream(os);
		return consoleAppender;
	}

	protected static Encoder<ILoggingEvent> getEncoder(LoggerContext lc, boolean encrypt) {
		PatternLayoutEncoder layoutEncoder = new PatternLayoutEncoder();
		layoutEncoder.setPattern(
		    "%-4relative %digest(%-5level - %msg){file=/tmp/testCmsEncWrappingEncoder.log,base64=true,algorithm=sha} %n");
		layoutEncoder.setContext(lc);
		layoutEncoder.setOutputPatternAsHeader(true);
		layoutEncoder.start();

		if (encrypt) {
			CmsWrappingEncryptionEncoder encoder = new CmsWrappingEncryptionEncoder();
			encoder.setBaseEncoder(layoutEncoder);
			encoder.setAlgorithm("AES/CBC/PKCS5Padding");
			encoder.addRecipient(TestUtils.getOriginatorKeyAndCertificate().getCertificateChain()[0]);
			return encoder;
		} else {
			return layoutEncoder;
		}
	}

	@After
	public void after() {
		lc.stop();
	}

	@Test
	public void testBasic() {
		root.addAppender(getFileAppender(lc));

		for (int i = 0; i < 10; ++i) {
			root.info("Hello World");
		}
		root.debug("Hello World");
	}

	@Test
	public void testDecrypt() {
		InputStream encodedIs = null;
		InputStream decryptedIs = null;
		BufferedOutputStream os = null;

		try {
			encodedIs = new BufferedInputStream(new FileInputStream("/tmp/testCmsEncWrappingEncoder.log"));
//			encodedIs = new BufferedInputStream(new FileInputStream("/tmp/CmsBdssEncoderLoggingInitializer.log"));
			EnvelopedDataStream envelopedStream = new EnvelopedDataStream(encodedIs);
			KeyAndCertificate recipient = TestUtils.getOriginatorKeyAndCertificate();
			envelopedStream.setupCipher(recipient.getPrivateKey(), recipient.getCertificateChain()[0]);
			envelopedStream.setBlockSize(2048);
			decryptedIs = envelopedStream.getInputStream();

//		IOUtils.copy(decryptedIs, System.err);
			os = new BufferedOutputStream(new FileOutputStream("/tmp/CmsBdssEncoderLoggingInitializer.log.txt"));
			IOUtils.copy(decryptedIs, os);
		} catch (Exception cause) {
			throw new RuntimeException(cause);
		} finally {
			CloseUtil.closeQuietly(encodedIs);
			CloseUtil.closeQuietly(decryptedIs);
			CloseUtil.closeQuietly(os);
		}
		for (int i = 0; i < 10; ++i) {
			root.info("Hello World");
		}
		root.debug("Hello World");
	}
}
