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
package iaik.privlog.helper;

import java.io.OutputStream;
import java.io.PrintStream;

import ch.qos.logback.core.status.OnConsoleStatusListener;

public class OnPrintStreamStatusListener extends OnConsoleStatusListener {

	protected final PrintStream printStream;

	public OnPrintStreamStatusListener(OutputStream outputStream) {
		this.printStream = new PrintStream(outputStream);
	}

	@Override
	protected PrintStream getPrintStream() {
		return printStream;
	}
}
