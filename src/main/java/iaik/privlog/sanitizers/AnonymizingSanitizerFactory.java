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
package iaik.privlog.sanitizers;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class AnonymizingSanitizerFactory extends BlindingSanitizerFactory {

	public AnonymizingSanitizerFactory() {
		blindingMask = null;
	}

	@Override
	public final boolean isMaskCritical() {
		return true;
	}

	@Override
	public void setMaskCritical(boolean maskCritical) {
		if (!maskCritical) {
			throw new UnsupportedOperationException("For the anonymizing sanitizer the critical value must be masked");
		}
	}

}
