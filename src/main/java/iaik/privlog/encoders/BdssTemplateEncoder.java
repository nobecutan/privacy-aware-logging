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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.helpers.Util;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.pattern.MDCConverter;
import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Context;
import ch.qos.logback.core.CoreConstants;
import ch.qos.logback.core.encoder.EncoderBase;
import ch.qos.logback.core.pattern.Converter;
import ch.qos.logback.core.pattern.ConverterUtil;
import ch.qos.logback.core.pattern.LiteralConverter;
import ch.qos.logback.core.pattern.parser.Node;
import ch.qos.logback.core.pattern.parser.Parser;
import ch.qos.logback.core.spi.ScanException;
import iaik.privlog.PrivacyAwareLoggingEvent;
import iaik.privlog.sanitizers.IParamSanitizer;
import iaik.privlog.sanitizers.IParamSanitizerFactory;
import iaik.utils.KeyAndCertificate;
import iaik.x509.X509Certificate;
import tug.iaik.blanksig.keys.PP;
import tug.iaik.blanksig.parameters.SingleProxyOSPS;
import tug.iaik.blanksig.representation.EType;
import tug.iaik.blanksig.representation.MessageEntry;
import tug.iaik.blanksig.representation.Template;
import tug.iaik.common.provider.ProxyTypeObjectID;
import tug.iaik.common.provider.ProxyTypeSignatures;
import tug.iaik.common.signing.SystemParameters;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class BdssTemplateEncoder extends EncoderBase<ILoggingEvent> {

	/**
	 * Default pattern string for log output.
	 */
	static final String DEFAULT_CONVERSION_PATTERN = "%date%thread%level%logger%mdc%msg%exception";
	/**
	 * Default number of log entries per template.
	 */
	static final int DEFAULT_NUM_INVOCATIONS = 15;

	protected Object lock = new Object();
	protected Thread shutdownHook;

	protected Template template;
	protected SystemParameters systemParameters;
	protected int numInvocations = DEFAULT_NUM_INVOCATIONS;
	protected int currentInvocations = 0;
	protected int templateId = 0;
	protected X509Certificate publicParametersCertificate;
	protected PP publicParameters;
	protected X509Certificate proxyCertificate;
	protected X509Certificate originatorCertificate;
	protected PrivateKey originatorSigningKey;
	protected Marshaller marshaller;

	protected String pattern = DEFAULT_CONVERSION_PATTERN;
	protected Converter<ILoggingEvent> head;

	@Override
	public void doEncode(ILoggingEvent evnt)
	    throws IOException
	{
		if (!isStarted()) {
			addError("The message processor " + getClass().getName() + " has not been started.");
			return;
		}

		PrivacyAwareLoggingEvent event = (PrivacyAwareLoggingEvent) evnt;
		synchronized (lock) {
			Converter<ILoggingEvent> c = head;
			StringBuilder fixedPart = new StringBuilder();
			while (c != null) {
				if (c instanceof MessageConverter) {
					Collection<IParamSanitizer> params = event.getParameters();
					String mt = event.getMessage();
					int curPos = 0;

					for (IParamSanitizer param : params) {
						if (param.getStartOriginal() > curPos) { // Fixed part
							fixedPart.append(mt.substring(curPos, param.getStart()));
						}
						if (param.isCriticalAndSanitizedEqual()) {
							fixedPart.append(param.getCritical());
						} else {
							if (fixedPart.length() > 0) { // First add fixed part
								template.addT(Arrays.asList(new MessageEntry(fixedPart.toString(), 0, EType.fix)));
								fixedPart.setLength(0);
							}
							template.addT(Arrays.asList(new MessageEntry(param.getCritical(), 0, EType.exch),
							    new MessageEntry(param.getSanitized(), 1, EType.exch)));
						}
						curPos = param.getStart() + 2;
					}
					if (curPos < mt.length()) {
						fixedPart.append(mt.substring(curPos, mt.length()));
					}
				} else {
					String txt = c.convert(event);
					if (txt.length() > 0) {
						if (c instanceof LiteralConverter) {
							fixedPart.append(txt);
						} else {
							String name = computeConverterName(c);
							IParamSanitizerFactory sanFact = event.getSanitizers().get(name);
							if (sanFact != null) {
								IParamSanitizer param = sanFact.create(name, txt, -1, -1, -1);
								if (param.isCriticalAndSanitizedEqual()) {
									fixedPart.append(param.getCritical());
								} else {
									if (fixedPart.length() > 0) { // First add fixed part
										template.addT(Arrays.asList(new MessageEntry(fixedPart.toString(), 0, EType.fix)));
										fixedPart.setLength(0);
									}
									template.addT(Arrays.asList(new MessageEntry(param.getCritical(), 0, EType.exch),
									    new MessageEntry(param.getSanitized(), 1, EType.exch)));
								}
							} else {
								if (fixedPart.length() > 0) { // First add fixed part
									template.addT(Arrays.asList(new MessageEntry(fixedPart.toString(), 0, EType.fix)));
									fixedPart.setLength(0);
								}
								template.addT(Arrays.asList(new MessageEntry(txt, 0, EType.blank)));
							}

						}
					}
				}

				c = c.getNext();
			}
			if (fixedPart.length() > 0) { // Still something left
				template.addT(Arrays.asList(new MessageEntry(fixedPart.toString(), 0, EType.fix)));
			}

			if (numInvocations > 1) { // Add next-record marker
				template.addT(Arrays.asList(new MessageEntry(System.lineSeparator(), -1, EType.fix)));
			}

			if (++currentInvocations >= numInvocations) {
				try { // Issue signature
					issueSignature();
				} finally {
					template = new Template("Logging Template " + (templateId++));
					currentInvocations = 0;
				}
			}
		}
	}

	@Override
	public void init(OutputStream os)
	    throws IOException
	{
		super.init(os);
		if (numInvocations > 0) {
			shutdownHook = new Thread(new Runnable() {

				@Override
				public void run() {
					try {
						close();
					} catch (Exception e) {
						// We tried at least.
					}
				}
			});
		}

		Runtime.getRuntime().addShutdownHook(shutdownHook);
	}

	@Override
	public void close()
	    throws IOException
	{
		try {
			if (currentInvocations > 0) {
				try { // Issue signature
					issueSignature();
				} finally {
					template = new Template("Logging Template " + (templateId++));
					currentInvocations = 0;
				}
			}
		} finally {
			if (shutdownHook != null) {
				Runtime.getRuntime().removeShutdownHook(shutdownHook);
				shutdownHook = null;
			}
		}
	}

	protected String computeConverterName(Converter<?> c) {
		if (c instanceof MDCConverter) {
			MDCConverter mc = (MDCConverter) c;
			String key = mc.getFirstOption();
			if (key != null) {
				return key;
			} else {
				return "MDC";
			}
		} else {
			String className = c.getClass().getSimpleName();
			int index = className.indexOf("Converter");
			if (index == -1) {
				return className;
			} else {
				return className.substring(0, index);
			}
		}
	}

	protected void issueSignature() {
		try {
			String signingAlg = systemParameters.getParameter(SystemParameters.ORIG_SIGNATURE_ID);
			Signature sig = Signature.getInstance(ProxyTypeObjectID.BDSSTemplateSignature);

			SingleProxyOSPS param = new SingleProxyOSPS(publicParameters, proxyCertificate, systemParameters,
			    DigestUtils.sha1(proxyCertificate.getEncoded()));

			sig.initSign(originatorSigningKey);
			sig.setParameter(param);
			sig.update(template.toByteArray());

			byte[] sigBytes = sig.sign();

			tug.iaik.common.representation.Signature s = new tug.iaik.common.representation.Signature(sigBytes,
			    publicParametersCertificate, originatorCertificate, proxyCertificate);

			s.setOrigAlg(signingAlg);
			template.setSignature(s);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			marshaller.marshal(template, bos);

			outputStream.write(bos.toByteArray());
			outputStream.write(System.lineSeparator().getBytes());
			outputStream.flush();
		} catch (Exception cause) {
			addError("Failed to issue BDSS template signature.", cause);
			throw cause instanceof RuntimeException ? (RuntimeException) cause
			    : new RuntimeException("Failed to issue BDSS template signature.", cause);
		}
	}

	@Override
	public void start() {
		if (context == null) {
			Util.report("BdssMessageProcessor cannot be started w/o a context");
			throw new RuntimeException("BdssMessageProcessor cannot be started w/o a context");
		}

		if (systemParameters == null) {
			systemParameters = new SystemParameters(createStandardConfiguration());
		}

		if (publicParametersCertificate == null) {
			addError("BdssMessageProcessor cannot be started w/o a public parameter certificate");
			return;
		}

		if (proxyCertificate == null) {
			addError("BdssMessageProcessor cannot be started w/o the proxies certificate");
			return;
		}

		if (originatorCertificate == null) {
			addError("BdssMessageProcessor cannot be started w/o the originators certificate");
			return;
		}

		if (originatorSigningKey == null) {
			addError("BdssMessageProcessor cannot be started w/o the originators signing key");
			return;
		}

		try {
			publicParameters = PP.decodeX509(publicParametersCertificate.getPublicKey().getEncoded());
		} catch (Exception cause) {
			addError("BdssMessageProcessor: The public parameters cannot be decoded from the provided certificate");
			return;
		}

		try {
			marshaller = JAXBContext.newInstance(Template.class).createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		} catch (Exception cause) {
			addError("BdssMessageProcessor: The JAXB marshaller could not be instantiated");
			return;
		}

		try {
			Parser<ILoggingEvent> p = new Parser<>(pattern);
			p.setContext(getContext());
			Node t = p.parse();
			this.head = p.compile(t, getEffectiveConverterMap());
			ConverterUtil.startConverters(this.head);
		} catch (ScanException ex) {
			addError("Incorrect pattern found", ex);
			return;
		}

		ProxyTypeSignatures.registerAsProvider();
		template = new Template("Logging Template " + (templateId++));
		started = true;
	}

	protected Map<String, String> getDefaultConverterMap() {
		return PatternLayout.defaultConverterMap;
	}

	/**
	 * Returns a map where the default converter map is merged with the map
	 * contained in the context.
	 */
	protected Map<String, String> getEffectiveConverterMap() {
		Map<String, String> effectiveMap = new HashMap<String, String>();

		// add the least specific map fist
		Map<String, String> defaultMap = getDefaultConverterMap();
		if (defaultMap != null) {
			effectiveMap.putAll(defaultMap);
		}

		// contextMap is more specific than the default map
		Context context = getContext();
		if (context != null) {
			@SuppressWarnings("unchecked")
			Map<String, String> contextMap = (Map<String, String>) context.getObject(CoreConstants.PATTERN_RULE_REGISTRY);
			if (contextMap != null) {
				effectiveMap.putAll(contextMap);
			}
		}
		return effectiveMap;
	}

	/**
	 * @return the standard configuration
	 */
	protected Properties createStandardConfiguration() {
		Properties p = new Properties();
		p.put(SystemParameters.SECURE_RANDOM_ID, "SHA256PRNG");
		p.put(SystemParameters.ORIG_SIGNATURE_ID, "SHA256withRSA");
		p.put(SystemParameters.PROXY_SIGNATURE_ID, "SHA256withRSA");
		p.put(SystemParameters.KEY_AGREEMENT_ID, "ECMQV");
		p.put(SystemParameters.ECIES_KDF_KEY_LENGTH, "128");
		p.put(SystemParameters.ECIES_KDF_MESSAGE_DIGEST, "SHA256");
		p.put(SystemParameters.ECIES_SYMMETRIC_CIPHER_NAME, "XOR");
		p.put(SystemParameters.ECIES_MAC_NAME, "HMAC/SHA");
		p.put(SystemParameters.BN_CURVE_BITLENGTH, "256");
		p.put(SystemParameters.MESSAGE_DIGEST_ID, "SHA256");
		return p;
	}

	public void setSystemParameters(SystemParameters systemParameters) {
		this.systemParameters = systemParameters;
	}

	public void setSystemParameters(Properties systemParameters) {
		this.systemParameters = new SystemParameters(systemParameters);
	}

	public void setNumInvocations(int numInvocations) {
		if (numInvocations <= 0) {
			throw new IllegalArgumentException("Parameter numInvocations greater than 0");
		}
		this.numInvocations = numInvocations;
	}

	public void setPublicParametersCertificate(java.security.cert.X509Certificate publicParametersCertificate) {
		try {
			this.publicParametersCertificate = publicParametersCertificate instanceof X509Certificate
			    ? (X509Certificate) publicParametersCertificate
			    : new X509Certificate(publicParametersCertificate.getEncoded());
		} catch (Exception cause) {
			throw new RuntimeException("Failed to convert X.509 certificate", cause);
		}
	}

	public void setProxyCertificate(java.security.cert.X509Certificate proxyCertificate) {
		try {
			this.proxyCertificate = proxyCertificate instanceof X509Certificate ? (X509Certificate) proxyCertificate
			    : new X509Certificate(proxyCertificate.getEncoded());
		} catch (Exception cause) {
			throw new RuntimeException("Failed to convert X.509 certificate", cause);
		}
	}

	public void setOriginatorCertificate(java.security.cert.X509Certificate originatorCertificate) {
		try {
			this.originatorCertificate = originatorCertificate instanceof X509Certificate
			    ? (X509Certificate) originatorCertificate : new X509Certificate(originatorCertificate.getEncoded());
		} catch (Exception cause) {
			throw new RuntimeException("Failed to convert X.509 certificate", cause);
		}
	}

	public void setOriginatorSigningKey(PrivateKey originatorSigningKey) {
		this.originatorSigningKey = originatorSigningKey;
	}

	public void setOriginatorKeyAndCertificate(KeyAndCertificate keyAndCertificate) {
		setOriginatorCertificate(keyAndCertificate.getCertificateChain()[0]);
		setOriginatorSigningKey(keyAndCertificate.getPrivateKey());
	}

	public String getPattern() {
		return pattern;
	}

	public void setPattern(String pattern) {
		this.pattern = pattern;
	}

}
