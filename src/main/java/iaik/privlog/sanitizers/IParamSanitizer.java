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

import org.slf4j.helpers.MessageFormatter;

/**
 * This interface holds the privacy sanitizer for a single log message
 * parameter.
 *
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public interface IParamSanitizer {

	/**
	 * Returns the string representation of the corresponding parameter. This
	 * could be the output of {@link MessageFormatter#format(String, Object)}.
	 *
	 * @return The string representation of the corresponding parameter.
	 */
	String getCritical();

	/**
	 * @return The sanitized, i.e., not privacy critical, substitution of the
	 *         corresponding parameter.
	 */
	String getSanitized();

	/**
	 * @return <code>true</code>, if {@link #getCritical()} and
	 *         {@link #getSanitized()} return the same string.
	 */
	boolean isCriticalAndSanitizedEqual();

	/**
	 * Returns the start position of the corresponding tag in the resulting
	 * message template (where all tags have been removed), e.g., for the original
	 * message template <code>"This is a {one} {two} message"</code> (resulting in
	 * the message template <code>"This is a {} {} message"</code>) this function
	 * will return <code>10</code> for the first parameter and <code>13</code> for
	 * the second.
	 *
	 * @return The start position of the corresponding tag in the resulting
	 *         message template.
	 */
	int getStart();

	/**
	 * Returns the start position of the corresponding tag in the original message
	 * template, e.g., for the message template
	 * <code>"This is a {one} {two} message"</code> this function will return
	 * <code>10</code> for the first parameter and <code>16</code> for the second.
	 *
	 * @return The start position of the corresponding tag in the original message
	 *         template.
	 */
	int getStartOriginal();

	/**
	 * Returns the end position of the corresponding tag in the message template,
	 * e.g., for the message template <code>"This is a {one} {two} message"</code>
	 * this function will return <code>14</code> for the first parameter and
	 * <code>20</code> for the second.
	 *
	 * @return The end position of corresponding tag in the message template.
	 */
	int getEndOriginal();

}
