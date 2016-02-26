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
package iaik.privlog.helper;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import ch.qos.logback.core.util.CloseUtil;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class TestUtils {

	public static X509Certificate getProxyCert() {
		return getX509Certificate("/iaik/privlog/bdss/proxy.cer");
	}

	public static X509Certificate getBdssPublicParameterCert() {
		return getX509Certificate("/iaik/privlog/bdss/pp.cer");
	}

	public static X509Certificate getX509Certificate(String resource) {
		InputStream is = null;

		try {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			is = resolveResourceAsStream(resource);
			return (X509Certificate) certFactory.generateCertificate(is);
		} catch (Exception cause) {
			throw cause instanceof RuntimeException ? (RuntimeException) cause
			    : new RuntimeException("Failed to load X.509 certificate [" + resource + "]", cause);
		} finally {
			CloseUtil.closeQuietly(is);
		}
	}

	public static KeyAndCertificate getOriginatorKeyAndCertificate() {

		InputStream isOriginatorKs = null;

		try {
			KeyStore keystore = KeyStore.getInstance("PKCS12", IAIK.getInstance());
			isOriginatorKs = resolveResourceAsStream("/iaik/privlog/bdss/originator.p12");
			char[] ksPassword = "password".toCharArray();
			keystore.load(isOriginatorKs, ksPassword);
			String alias = keystore.aliases().nextElement();
			return new KeyAndCertificate((PrivateKey) keystore.getKey(alias, ksPassword),
			    (iaik.x509.X509Certificate[]) keystore.getCertificateChain(alias));
		} catch (Exception cause) {
			throw cause instanceof RuntimeException ? (RuntimeException) cause
			    : new RuntimeException("Failed to load public parameters certificate.", cause);
		} finally {
			CloseUtil.closeQuietly(isOriginatorKs);
		}

	}

	/**
	 * Same as {@link java.lang.Class#getResourceAsStream()} but works with and
	 * without jars reliably. In fact the resource is tried to be loaded with and
	 * without / in front of the path. The method needs ClassLoader to be able to
	 * load the resource. This is mainly intended for the usage with an add-on jar
	 * file.
	 *
	 * @param name
	 *        Name of the resource.
	 * @return Open stream to the resource or null if none found.
	 * @throws IOException
	 */
	public static InputStream resolveResourceAsStream(String name)
	    throws IOException
	{
		ClassLoader loader = TestUtils.class.getClassLoader();
		URL url = loader.getResource(name);
		if (url == null) {
			name = name.startsWith("/") ? name.substring(1) : "/" + name;
			url = loader.getResource(name);
		}
		if (url != null) {
			return new BufferedInputStream(url.openStream());
		}
		return null;
	}
}
