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

import org.xml.sax.Attributes;

import ch.qos.logback.core.joran.action.Action;
import ch.qos.logback.core.joran.spi.ActionException;
import ch.qos.logback.core.joran.spi.InterpretationContext;
import ch.qos.logback.core.spi.ContextAware;
import ch.qos.logback.core.spi.LifeCycle;
import ch.qos.logback.core.util.OptionHelper;
import iaik.privlog.IParamSanitizerFactoriesAware;
import iaik.privlog.sanitizers.IParamSanitizerFactory;

public class ParamSanitizerFactoryAction extends Action {

	public static final String TAG_NAME_ATTRIBUTE = "tagName";

	private boolean inError = false;
	private IParamSanitizerFactory sanitizerFactory;
	private String tagName;

	@Override
	public void begin(InterpretationContext ic, String localName, Attributes attributes)
	    throws ActionException
	{
		Object o = ic.peekObject();
		if (!(o instanceof IParamSanitizerFactoriesAware)) {
			addError("Parameter sanitizers work only for classes implementing IParamSanitizerFactoriesAware.");
			throw new ActionException(new RuntimeException(
			    "Parameter sanitizers work only for classes implementing IParamSanitizerFactoriesAware."));
		}

		tagName = ic.subst(attributes.getValue(TAG_NAME_ATTRIBUTE));
		if (OptionHelper.isEmpty(tagName)) {
			addError("Missing tag name for parameter sanitizer. Near [" + localName + "] line " + getLineNumber(ic));
			inError = true;
			return;
		}
		String className = attributes.getValue(CLASS_ATTRIBUTE);
		if (OptionHelper.isEmpty(className)) {
			addError("Missing class name for parameter sanitizer. Near [" + localName + "] line " + getLineNumber(ic));
			inError = true;
			return;
		}

		try {
			addInfo("About to instantiate appender of type [" + className + "] for tag name {" + tagName + "}");

			sanitizerFactory = (IParamSanitizerFactory) OptionHelper.instantiateByClassName(className,
			    IParamSanitizerFactory.class, context);

			ic.pushObject(sanitizerFactory);
		} catch (Exception oops) {
			inError = true;
			addError("Could not create an parameter sanitizer of type [" + className + "].", oops);
			throw new ActionException(oops);
		}

	}

	@Override
	public void end(InterpretationContext ic, String name)
	    throws ActionException
	{
		if (inError) {
			return;
		}

		Object o = ic.peekObject();

		if (o != sanitizerFactory) {
			addWarn("The object at the of the stack is not the parameter sanitizer for tag named {" + tagName
			    + "} pushed earlier.");
		} else {
			ic.popObject();

			try {
				if (sanitizerFactory instanceof ContextAware) {
					addInfo("Setting context for parameter sanitizer [" + tagName + "]");
					((ContextAware) sanitizerFactory).setContext(context);
				}
				if (sanitizerFactory instanceof LifeCycle) {
					addInfo("Starting parameter sanitizer [" + tagName + "]");
					LifeCycle component = (LifeCycle) sanitizerFactory;
					component.start();
					context.register(component);
				}
			} catch (Exception cause) {
				addError("Failed to start parameter sanitizer [" + tagName + "]", cause);
				throw new ActionException(cause);
			}

			// Add the sanitizer to the privacy aware appender
			o = ic.peekObject();
			if (o instanceof IParamSanitizerFactoriesAware) {
				((IParamSanitizerFactoriesAware) o).addSanitizerFactory(tagName, sanitizerFactory);
			} else {
				addError("Parameter sanitizers work only for classes implementing IParamSanitizersAware.");
				throw new ActionException(
				    new RuntimeException("Parameter sanitizers work only for classes implementing IParamSanitizersAware."));
			}
		}

	}

}
