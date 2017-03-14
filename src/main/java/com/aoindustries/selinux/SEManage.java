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

import com.aoindustries.lang.ProcessResult;
import com.aoindustries.util.WrappedException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wraps functions of the <code>semanage</code> commands.
 *
 * @author  AO Industries, Inc.
 */
public class SEManage {

	// Unused: private static final Logger logger = Logger.getLogger(SEManage.class.getName());

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

			PortNumber(int from, int to) {
				if(from < MIN_PORT) throw new IllegalArgumentException("from < MIN_PORT: " + from + " < " + MIN_PORT);
				if(from > MAX_PORT) throw new IllegalArgumentException("from > MAX_PORT: " + from + " > " + MAX_PORT);
				if(to < MIN_PORT) throw new IllegalArgumentException("to < MIN_PORT: " + to + " < " + MIN_PORT);
				if(to > MAX_PORT) throw new IllegalArgumentException("to > MAX_PORT: " + to + " > " + MAX_PORT);
				if(to < from) throw new IllegalArgumentException("to < from: " + to + " < " + from);
				this.from = from;
				this.to = to;
			}

			@Override
			public String toString() {
				if(from == to) return Integer.toString(from);
				return Integer.toString(from) + '-' + Integer.toString(to);
			}

			@Override
			public boolean equals(Object obj) {
				if(!(obj instanceof PortNumber)) return false;
				PortNumber other = (PortNumber)obj;
				return
					from == other.from
					&& to == other.to
				;
			}

			@Override
			public int hashCode() {
				return from * 31 + to;
			}

			public int getFrom() {
				return from;
			}

			public int getTo() {
				return to;
			}
		}

		private static final Pattern listPattern = Pattern.compile("^(\\S+)\\s+(\\S+)\\s+(\\S.*)$");

		/**
		 * Parses the output of <code>semanage port --noheading --list</code>.
		 *
		 * @return  the unmodifiable list of ports
		 */
		// Not private for unit testing
		static List<Port> parseList(String stdout) throws IOException {
			List<Port> ports = new ArrayList<Port>();
			BufferedReader in = new BufferedReader(new StringReader(stdout));
			String line;
			while((line = in.readLine()) != null) {
				try {
					Matcher matcher = listPattern.matcher(line);
					if(!matcher.find()) throw new IOException("Line not matched: " + line);
					assert matcher.groupCount() == 3;
					ports.add(
						new Port(
							matcher.group(1),
							Protocol.valueOf(matcher.group(2)),
							parsePortNumbers(matcher.group(3))
						)
					);
				} catch(IllegalStateException e) {
					throw new WrappedException("line = " + line, e);
				}
			}
			return Collections.unmodifiableList(ports);  
		}

		/**
		 * Parses the port number list.
		 *
		 * @return  the unmodifiable list of port numbers
		 */
		// Not private for unit testing
		static List<PortNumber> parsePortNumbers(String group) throws IOException {
			List<PortNumber> portNumbers = new ArrayList<PortNumber>();
			StringTokenizer tokens = new StringTokenizer(group, ", ");
			while(tokens.hasMoreTokens()) {
				String token = tokens.nextToken();
				int hyphenPos = token.indexOf('-');
				int from, to;
				if(hyphenPos == -1) {
					from = to = Integer.parseInt(token);
				} else {
					from = Integer.parseInt(token.substring(0, hyphenPos));
					to = Integer.parseInt(token.substring(hyphenPos + 1));
				}
				portNumbers.add(new PortNumber(from, to));
			}
			if(portNumbers.isEmpty()) throw new IOException("No port numbers found: " + group);
			return Collections.unmodifiableList(portNumbers);
		}

		/**
		 * Calls <code>semanage port --list</code>.
		 *
		 * @return  the unmodifiable list of ports
		 */
		public static List<Port> list() throws IOException {
			ProcessResult result;
			synchronized(semanageLock) {
				result = ProcessResult.exec(SEMANAGE_EXE, "port", "--noheading", "--list");
			}
			if(result.getExitVal() != 0) throw new IOException(result.getStderr());
			return parseList(result.getStdout());
		}

		/**
		 * Calls <code>semanage port --list --locallist</code>.
		 *
		 * @return  the unmodifiable list of ports
		 */
		public static List<Port> localList() throws IOException {
			ProcessResult result;
			synchronized(semanageLock) {
				result = ProcessResult.exec(SEMANAGE_EXE, "port", "--noheading", "--list", "--locallist");
			}
			if(result.getExitVal() != 0) throw new IOException(result.getStderr());
			return parseList(result.getStdout());
		}

		private final String type;
		private final Protocol protocol;
		private final List<PortNumber> portNumbers;

		Port(
			String type,
			Protocol protocol,
			List<PortNumber> portNumbers
		) {
			this.type = type;
			this.protocol = protocol;
			this.portNumbers = portNumbers;
		}

		@Override
		public String toString() {
			return "(" + type + ", " + protocol + ", " + portNumbers + ")";
		}

		@Override
		public boolean equals(Object obj) {
			if(!(obj instanceof Port)) return false;
			Port other = (Port)obj;
			return
				type.equals(other.type)
				&& protocol == other.protocol
				&& portNumbers.equals(other.portNumbers)
			;
		}

		@Override
		public int hashCode() {
			int hash = type.hashCode();
			hash = hash * 31 + protocol.hashCode();
			hash = hash * 31 + portNumbers.hashCode();
			return hash;
		}

		public String getType() {
			return type;
		}

		public Protocol getProtocol() {
			return protocol;
		}

		public List<PortNumber> getPortNumbers() {
			return portNumbers;
		}
	}

	/**
	 * Make no instances.
	 */
	private SEManage() {
	}
}
