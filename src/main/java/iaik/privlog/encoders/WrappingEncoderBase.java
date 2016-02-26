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

import ch.qos.logback.core.Context;
import ch.qos.logback.core.encoder.Encoder;
import ch.qos.logback.core.status.Status;

/**
 * @author Christof Rath <christof.rath@iaik.tugraz.at>
 */
public abstract class WrappingEncoderBase<U> implements Encoder<U> {

	protected Encoder<U> baseEncoder;

	@SuppressWarnings("unchecked")
	public void setBaseEncoder(Encoder<? extends U> baseEncoder) {
		this.baseEncoder = Encoder.class.cast(baseEncoder);
	}

	@Override
	public void doEncode(U event)
	    throws IOException
	{
		baseEncoder.doEncode(event);
	}

	@Override
	public void start() {
		baseEncoder.start();
	}

	@Override
	public void stop() {
		baseEncoder.stop();
	}

	@Override
	public boolean isStarted() {
		return baseEncoder.isStarted();
	}

	@Override
	public void setContext(Context context) {
		baseEncoder.setContext(context);
	}

	@Override
	public Context getContext() {
		return baseEncoder.getContext();
	}

	@Override
	public void addStatus(Status status) {
		baseEncoder.addStatus(status);
	}

	@Override
	public void addInfo(String msg) {
		baseEncoder.addInfo(msg);
	}

	@Override
	public void addInfo(String msg, Throwable ex) {
		baseEncoder.addInfo(msg, ex);
	}

	@Override
	public void addWarn(String msg) {
		baseEncoder.addWarn(msg);
	}

	@Override
	public void addWarn(String msg, Throwable ex) {
		baseEncoder.addWarn(msg, ex);
	}

	@Override
	public void addError(String msg) {
		baseEncoder.addError(msg);
	}

	@Override
	public void addError(String msg, Throwable ex) {
		baseEncoder.addError(msg, ex);
	}

	@Override
	public void init(OutputStream os)
	    throws IOException
	{
		baseEncoder.init(os);
	}

	@Override
	public void close()
	    throws IOException
	{
		baseEncoder.close();
	}

}
