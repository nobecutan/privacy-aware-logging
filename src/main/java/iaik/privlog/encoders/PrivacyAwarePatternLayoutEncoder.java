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

import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import iaik.privlog.layouts.PrivacyAwarePatternLayout;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class PrivacyAwarePatternLayoutEncoder extends PatternLayoutEncoder {

	@Override
	public void start() {
		PrivacyAwarePatternLayout patternLayout = new PrivacyAwarePatternLayout();
		patternLayout.setContext(context);
		patternLayout.setPattern(getPattern());
		patternLayout.setOutputPatternAsHeader(outputPatternAsHeader);
		patternLayout.start();
		this.layout = patternLayout;
		this.started = true; // The equivalent of super.super.start();
	}

}
