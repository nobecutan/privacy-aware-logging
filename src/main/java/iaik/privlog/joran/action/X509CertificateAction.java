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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.xml.sax.Attributes;

import ch.qos.logback.core.joran.action.Action;
import ch.qos.logback.core.joran.spi.ActionException;
import ch.qos.logback.core.joran.spi.InterpretationContext;
import ch.qos.logback.core.joran.util.PropertySetter;
import ch.qos.logback.core.util.CloseUtil;
import ch.qos.logback.core.util.OptionHelper;

public class X509CertificateAction extends Action {

	protected String targetProperty;
	protected X509Certificate x509Certificate;
	protected byte[] derEncoded;

	protected boolean inError;

	@Override
	public void begin(InterpretationContext ic, String localName, Attributes attributes)
	    throws ActionException
	{
		targetProperty = ic.subst(attributes.getValue(NAME_ATTRIBUTE));
		if (OptionHelper.isEmpty(targetProperty)) {
			addError("Missing name for target parameter. Near [" + localName + "] line " + getLineNumber(ic));
			inError = true;
			return;
		}

		String certFilename = ic.subst(attributes.getValue(FILE_ATTRIBUTE));
		if (!OptionHelper.isEmpty(certFilename)) {
			File certFile = new File(certFilename);

			BufferedInputStream bis = null;
			try {
				bis = new BufferedInputStream(new FileInputStream(certFile));
				CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
				x509Certificate = (X509Certificate) certFactory.generateCertificate(bis);
			} catch (FileNotFoundException e) {
				addError("Cannot read certificate file [" + certFile.getAbsolutePath() + " ]. Near [" + localName + "] line "
				    + getLineNumber(ic));
				inError = true;
			} catch (CertificateException cause) {
				addError("Cannot read certificate file [" + certFile.getAbsolutePath() + " ]. Cause: " + cause.getMessage()
				    + ". Near [" + localName + "] line " + getLineNumber(ic));
				inError = true;
				throw new ActionException(cause);
			} finally {
				CloseUtil.closeQuietly(bis);
			}
		}

	}

	@Override
	public void body(InterpretationContext ic, String body)
	    throws ActionException
	{
		if (inError) {
			return;
		}

		String mod = body.replaceAll("(?m)(^\\s*|\\s*$)", "")
		    .replaceAll("(-+BEGIN CERTIFICATE-+\r?\n?|-+END CERTIFICATE-+)", "");

		Base64 base64 = new Base64();
		BufferedInputStream bis = null;
		try {
			bis = new BufferedInputStream(new ByteArrayInputStream(base64.decode(mod)));
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			x509Certificate = (X509Certificate) certFactory.generateCertificate(bis);
		} catch (Exception cause) {
			addError("Cannot read certificate data. Cause: " + cause.getMessage() + ". Near line " + getLineNumber(ic));
			inError = true;
			throw new ActionException(cause);
		} finally {
			CloseUtil.closeQuietly(bis);
		}

	}

	@Override
	public void end(InterpretationContext ic, String localName)
	    throws ActionException
	{
		if (inError) {
			return;
		}

		if (x509Certificate == null) {
			addError("X.509 certificate configuration is invalid. Near [" + localName + "] line " + getLineNumber(ic));
		} else {
			Object o = ic.peekObject();
			addInfo("Set certificate with subject DN [" + x509Certificate.getSubjectDN() + "] to property [" + targetProperty
			    + "] of object [" + o + "].");
			PropertySetter setter = new PropertySetter(o);
			setter.setComplexProperty(targetProperty, x509Certificate);
		}
	}
}
