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

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.util.CloseUtil;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.ContentInfoOutputStream;
import iaik.cms.EnvelopedDataOutputStream;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.utils.Util;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class CmsWrappingEncryptionEncoder extends WrappingEncoderBase<ILoggingEvent> {

	protected EnvelopedDataOutputStream envelopedDataOutputStream;
	protected String algorithm;
	protected Thread shutdownHook;
	protected ArrayList<RecipientInfo> recipients = new ArrayList<>();

	@Override
	public void init(OutputStream os)
	    throws IOException
	{
		try {
			ContentInfoOutputStream contentInfoStream = new ContentInfoOutputStream(ObjectID.cms_envelopedData, os);
			contentInfoStream.setPassThroughClose(false);

			AlgorithmID contentEncAlg = (AlgorithmID) AlgorithmID.getAlgorithmID(algorithm).clone();
			envelopedDataOutputStream = new EnvelopedDataOutputStream(contentInfoStream, contentEncAlg);

			for (RecipientInfo recipientInfo : recipients) {
				envelopedDataOutputStream.addRecipientInfo(recipientInfo);
			}

			baseEncoder.init(envelopedDataOutputStream);
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

			Runtime.getRuntime().addShutdownHook(shutdownHook);
		} catch (Exception cause) {
			addError("Failed to initialize CMS output stream", cause);
		}
	}

	@Override
	public void close()
	    throws IOException
	{
		try {
			baseEncoder.close();
			envelopedDataOutputStream.flush();
		} finally {
			CloseUtil.closeQuietly(envelopedDataOutputStream);
			envelopedDataOutputStream = null;
			Runtime.getRuntime().removeShutdownHook(shutdownHook);
			shutdownHook = null;
		}
	}

	public void addRecipientInfo(RecipientInfo recipientInfo) {
		recipients.add(recipientInfo);
	}

	public void addRecipient(X509Certificate encyptionCertificate) {
		addRecipient(encyptionCertificate, getKeyTransEncAlgorithm(encyptionCertificate));
	}

	public void addRecipient(X509Certificate encyptionCertificate, AlgorithmID algorithmID) {
		try {
			RecipientInfo recipientInfo = new KeyTransRecipientInfo(Util.convertCertificate(encyptionCertificate),
			    algorithmID);
			addRecipientInfo(recipientInfo);
		} catch (Exception cause) {
			throw cause instanceof RuntimeException ? (RuntimeException) cause
			    : new RuntimeException("Failed to add recipient via encryption certificate", cause);
		}

	}

	protected AlgorithmID getKeyTransEncAlgorithm(X509Certificate encyptionCertificate) {
		if ("RSA".equals(encyptionCertificate.getPublicKey().getAlgorithm())) {
			return (AlgorithmID) AlgorithmID.rsaesOAEP.clone();
		} else {
			throw new IllegalArgumentException("Currently only RSA encryption certificates are supported");
		}
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

}
