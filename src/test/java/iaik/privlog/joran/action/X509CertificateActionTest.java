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
package iaik.privlog.joran.action;

import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.net.URL;

import org.hamcrest.Description;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentMatcher;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.status.Status;
import ch.qos.logback.core.status.StatusListener;
import ch.qos.logback.core.util.Loader;
import iaik.privlog.joran.PrivacyAwareJoranConfigurator;
import iaik.security.provider.IAIK;

public class X509CertificateActionTest {

	StatusListener mockStatusListener = mock(StatusListener.class);

	protected Status getStatusMatcher(final int level, final String target) {
		return argThat(new ArgumentMatcher<Status>() {

			@Override
			public boolean matches(final Object argument) {
				Status s = (Status) argument;
				return s.getEffectiveLevel() == level && s.getMessage().startsWith(target);
			}

			@Override
			public void describeTo(Description description) {
				description.appendText("startsWith(\"" + target + "\")");
			}
		});
	}

	@BeforeClass
	public static void setup() {
		IAIK.addAsProvider(true);
	}

	@Test
	public void testEmptyConfiguration() {
		LoggerContext lc = new LoggerContext();
		lc.getStatusManager().add(mockStatusListener);

		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/joran/action/configX509Certificate1.xml");
			jc.doConfigure(configFile);
			verify(mockStatusListener, times(1))
			    .addStatusEvent(getStatusMatcher(Status.ERROR, "Missing name for target parameter. Near [x509Certificate]"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	@Test
	public void testMissingCertificateConfiguration() {
		LoggerContext lc = new LoggerContext();
		lc.getStatusManager().add(mockStatusListener);

		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/joran/action/configX509Certificate2.xml");
			jc.doConfigure(configFile);
			verify(mockStatusListener, times(1)).addStatusEvent(
			    getStatusMatcher(Status.ERROR, "X.509 certificate configuration is invalid. Near [x509Certificate]"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	@Test
	public void testInvalidCertificateFileConfiguration() {
		LoggerContext lc = new LoggerContext();
		lc.getStatusManager().add(mockStatusListener);

		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/joran/action/configX509Certificate3.xml");
			jc.doConfigure(configFile);
			verify(mockStatusListener, times(1))
			    .addStatusEvent(getStatusMatcher(Status.ERROR, "Cannot read certificate file ["));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	@Test
	public void testInvalidBodyContentConfiguration() {
		LoggerContext lc = new LoggerContext();
		lc.getStatusManager().add(mockStatusListener);

		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/joran/action/configX509Certificate4.xml");
			jc.doConfigure(configFile);
			verify(mockStatusListener, times(1))
			    .addStatusEvent(getStatusMatcher(Status.ERROR, "Cannot read certificate data. Cause: iaik.asn1.DerCoder"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	@Test
	public void testValidBodyContentConfiguration() {
		LoggerContext lc = new LoggerContext();
		lc.getStatusManager().add(mockStatusListener);

		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/joran/action/configX509Certificate5.xml");
			jc.doConfigure(configFile);
			verify(mockStatusListener, times(1)).addStatusEvent(getStatusMatcher(Status.INFO,
			    "Set certificate with subject DN [CN=DI Christof Rath,T=DI,givenName=Christof,SN=Rath,OU=Institute for Applied Information Processing and Communications,O=Graz University of Technology,L=Graz,C=AT] to property [encCertificate] of object [iaik.privlog.sanitizers.RsaEncSanitizerFactory"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void testValidCertificatePemFileConfiguration() {
		LoggerContext lc = new LoggerContext();
		lc.getStatusManager().add(mockStatusListener);

		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/joran/action/configX509Certificate6.xml");
			jc.doConfigure(configFile);
			verify(mockStatusListener, times(1)).addStatusEvent(getStatusMatcher(Status.INFO,
			    "Set certificate with subject DN [CN=DI Christof Rath,T=DI,givenName=Christof,SN=Rath,OU=Institute for Applied Information Processing and Communications,O=Graz University of Technology,L=Graz,C=AT] to property [encCertificate] of object [iaik.privlog.sanitizers.RsaEncSanitizerFactory"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		Logger logger = lc.getLogger(getClass());
		long start = System.currentTimeMillis();
		int num = 1000;
		for (int i = 0; i < num; ++i) {
			logger.debug("Hello Username {username}", "crath");
		}
		logger.debug("Time for {} invocations: {}", num, System.currentTimeMillis() - start);
	}

	@Test
	public void testValidCertificateDerFileConfiguration() {
		LoggerContext lc = new LoggerContext();
		lc.getStatusManager().add(mockStatusListener);

		JoranConfigurator jc = new PrivacyAwareJoranConfigurator();
		jc.setContext(lc);
		try {
			URL configFile = Loader.getResourceBySelfClassLoader("iaik/privlog/joran/action/configX509Certificate7.xml");
			jc.doConfigure(configFile);
			verify(mockStatusListener, times(0)).addStatusEvent(getStatusMatcher(Status.ERROR, ""));
			verify(mockStatusListener, times(1)).addStatusEvent(getStatusMatcher(Status.INFO,
			    "Set certificate with subject DN [CN=IAIK CA,OU=IAIK,O=Graz University of Technology,L=Graz,C=AT] to property [encCertificate] of object [iaik.privlog.sanitizers.RsaEncSanitizerFactory"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

}
