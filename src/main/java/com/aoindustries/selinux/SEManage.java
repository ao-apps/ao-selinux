/*
 * ao-selinux - Java API for managing Security-Enhanced Linux (SELinux).
 * Copyright (C) 2017  AO Industries, Inc.
 *     support@aoindustries.com
 *     7262 Bull Pen Cir
 *     Mobile, AL 36695
 *
 * This file is part of ao-selinux.
 *
 * ao-selinux is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ao-selinux is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with ao-selinux.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aoindustries.selinux;

import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

/**
 * Wraps functions of the <code>semanage</code> commands.
 *
 * @author  AO Industries, Inc.
 */
public class SEManage {

	private static final Logger logger = Logger.getLogger(SEManage.class.getName());

	/**
	 * The full path to the <code>semanage</code> executable.
	 */
	private static final String SEMANAGE_EXE = "/usr/sbin/semanage";

	/**
	 * Serializes access to the underlying <code>semanage</code> command.
	 */
	private static class SemanageLock {}
	private static final SemanageLock semanageLock = new SemanageLock();

	/**
	 * Wraps functions of the <code>semanage port</code> commands.
	 */
	public static class Port {

		public enum Protocol {
			tcp,
			udp
		}

		/**
		 * Port numbers may be a single port or a range of ports.
		 * When a single port, this will have the same from and to port.
		 */
		public static class PortNumber {

			public static final int MIN_PORT = 1;
			public static final int MAX_PORT = 65535;

			private final int from;
			private final int to;

			public PortNumber(int from, int to) {
				if(from < MIN_PORT) throw new IllegalArgumentException("from < MIN_PORT: " + from + " < " + MIN_PORT);
				if(from > MAX_PORT) throw new IllegalArgumentException("from > MAX_PORT: " + from + " > " + MAX_PORT);
				if(to < MIN_PORT) throw new IllegalArgumentException("to < MIN_PORT: " + to + " < " + MIN_PORT);
				if(to > MAX_PORT) throw new IllegalArgumentException("to > MAX_PORT: " + to + " > " + MAX_PORT);
				if(to < from) throw new IllegalArgumentException("to < from: " + to + " < " + from);
				this.from = from;
				this.to = to;
			}
		}

		/**
		 * Calls <code>semanage port --noheading --list [--locallist]</code>.
		 */
		private static List<Port> list(boolean localList) throws IOException {
			String[] command;
			if(localList) {
				command = new String[] {
					SEMANAGE_EXE,
					"port",
					"--noheading",
					"--list",
					"--locallist"
				};
			} else {
				command = new String[] {
					SEMANAGE_EXE,
					"port",
					"--noheading",
					"--list"
				};
			}
			synchronized(semanageLock) {
				// TODO: Use ProcessResult
				Process p = Runtime.getRuntime().exec(command);
				// No output to the command
				p.getOutputStream().close();
			}
		}

		/**
		 * Calls <code>semanage port --list</code>.
		 */
		public static List<Port> list() throws IOException {
			return list(false);
		}

		/**
		 * Calls <code>semanage port --list --locallist</code>.
		 */
		public static List<Port> localList() throws IOException {
			return list(true);
		}

		private final String type;
		private final Protocol protocol;
		private final List<PortNumber> portNumbers;

		/**
		 * Make no instances.
		 */
		private Port() {
		}
	}

	/**
	 * Make no instances.
	 */
	private SEManage() {
	}
}
