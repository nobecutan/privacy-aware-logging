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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import iaik.privlog.PrivacyAwareLoggingEvent.NonCriticalTag;
import iaik.privlog.sanitizers.BlindingSanitizerFactory;
import iaik.privlog.sanitizers.BlindingSanitizerFactory.BlindingSanitizer;
import iaik.privlog.sanitizers.IParamSanitizer;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public class PrivacyAwareLoggingEventTest {
	protected ParamSanitizerFactories sanitizers;
	protected LoggerContext lc;
	private Object[] params;
	private String mt;

	@Before
	public void setup() {
		lc = new LoggerContext();
		params = new Object[] { "Hello", "World" };
		mt = "This is a {} message with {blind} data";

		sanitizers = new ParamSanitizerFactories();
		sanitizers.put("blind", new BlindingSanitizerFactory());
	}

	@Test
	public void testBuildLoggingEventType() {
		PrivacyAwareLoggingEvent e = PrivacyAwareLoggingEvent.build(sanitizers, "test", lc.getLogger("test"), Level.DEBUG,
		    mt, null, params);
		IParamSanitizer first = e.parameters.get(0);
		IParamSanitizer second = e.parameters.get(1);

		Assert.assertTrue("First tag is non critical", first instanceof NonCriticalTag);
		Assert.assertTrue("Second tag is to be blinded", second instanceof BlindingSanitizer);

	}

	@Test
	public void testBuildLoggingEventIndizes() {

		PrivacyAwareLoggingEvent e = PrivacyAwareLoggingEvent.build(sanitizers, "test", lc.getLogger("test"), Level.DEBUG,
		    mt, null, params);
		IParamSanitizer first = e.parameters.get(0);
		IParamSanitizer second = e.parameters.get(1);

		Assert.assertEquals("First tag should start at 10", mt.indexOf("{"), first.getStartOriginal());
		Assert.assertEquals("First tag should end at 11", mt.indexOf("}"), first.getEndOriginal());

		Assert.assertEquals("Second tag should start at 26", mt.lastIndexOf("{"), second.getStartOriginal());
		Assert.assertEquals("Second tag should end at 32", mt.lastIndexOf("}"), second.getEndOriginal());
	}

	@Test
	public void testBuildLoggingEventEqualsCriticalMessage() {

		PrivacyAwareLoggingEvent e = PrivacyAwareLoggingEvent.build(sanitizers, "test", lc.getLogger("test"), Level.DEBUG,
		    mt, null, params);
		IParamSanitizer first = e.parameters.get(0);
		IParamSanitizer second = e.parameters.get(1);

		StringBuilder sb = new StringBuilder();
		sb.append(mt.substring(0, first.getStartOriginal()));
		sb.append(params[0]);

		sb.append(mt.substring(first.getEndOriginal() + 1, second.getStartOriginal()));
		sb.append(params[1]);

		sb.append(mt.substring(second.getEndOriginal() + 1, mt.length()));

		Assert.assertEquals(e.getFullyDisclosedFormattedMessage(), sb.toString());
	}

	@Test
	public void testBuildLoggingEventEqualsSanitizedMessage() {

		PrivacyAwareLoggingEvent e = PrivacyAwareLoggingEvent.build(sanitizers, "test", lc.getLogger("test"), Level.DEBUG,
		    mt, null, params);
		IParamSanitizer first = e.parameters.get(0);
		IParamSanitizer second = e.parameters.get(1);

		StringBuilder sb = new StringBuilder();
		sb.append(mt.substring(0, first.getStartOriginal()));
		sb.append(params[0]);

		sb.append(mt.substring(first.getEndOriginal() + 1, second.getStartOriginal()));
		sb.append(BlindingSanitizerFactory.BLINDING_MASK);

		sb.append(mt.substring(second.getEndOriginal() + 1, mt.length()));

		Assert.assertEquals(e.getFormattedMessage(), sb.toString());
	}

}
