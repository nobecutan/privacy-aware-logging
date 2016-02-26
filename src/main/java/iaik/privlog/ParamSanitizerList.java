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

import java.util.ArrayList;

import iaik.privlog.sanitizers.IParamSanitizer;

class ParamSanitizerList extends ArrayList<IParamSanitizer> {
	private static final long serialVersionUID = 3995018917636444246L;

	private String[] criticalValues;
	private String[] sanitizedValues;

	String[] getCritical() {
		if (criticalValues == null) {
			ArrayList<String> values = new ArrayList<String>(size());
			for (IParamSanitizer sanitizer : this) {
				values.add(sanitizer.getCritical());
			}

			criticalValues = values.toArray(new String[size()]);
		}
		return criticalValues;
	}

	String[] getSanitized() {
		if (sanitizedValues == null) {
			ArrayList<String> values = new ArrayList<String>(size());
			for (IParamSanitizer sanitizer : this) {
				values.add(sanitizer.getSanitized());
			}

			sanitizedValues = values.toArray(new String[size()]);
		}
		return sanitizedValues;
	}
}
