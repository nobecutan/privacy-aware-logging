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
package iaik.privlog.joran;

import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.action.AppenderRefAction;
import ch.qos.logback.core.joran.spi.ElementSelector;
import ch.qos.logback.core.joran.spi.RuleStore;
import iaik.privlog.joran.action.ParamSanitizerFactoryAction;
import iaik.privlog.joran.action.X509CertificateAction;

public class PrivacyAwareJoranConfigurator extends JoranConfigurator {

	@Override
	@SuppressWarnings("rawtypes")
	public void addInstanceRules(RuleStore rs) {
		// parent rules already added
		super.addInstanceRules(rs);

		rs.addRule(new ElementSelector("*/paramSanitizer"), new ParamSanitizerFactoryAction());
		rs.addRule(new ElementSelector("*/appender/appender-ref"), new AppenderRefAction());

		rs.addRule(new ElementSelector("*/x509Certificate"), new X509CertificateAction());
	}

}
