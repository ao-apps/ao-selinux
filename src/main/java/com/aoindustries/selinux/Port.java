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

import com.aoindustries.util.WrappedException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wraps functions of the <code>semanage port</code> commands.
 *
 * @author  AO Industries, Inc.
 */
public class Port {

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
						PortNumber.parsePortNumbers(matcher.group(3))
					)
				);
			} catch(IllegalStateException e) {
				throw new WrappedException("line = " + line, e);
			}
		}
		return Collections.unmodifiableList(ports);  
	}

	/**
	 * Calls <code>semanage port --list</code>.
	 *
	 * @return  the unmodifiable list of ports
	 */
	public static List<Port> list() throws IOException {
		return parseList(SEManage.execSemanage("port", "--noheading", "--list").getStdout());
	}

	/**
	 * Calls <code>semanage port --list --locallist</code>.
	 *
	 * @return  the unmodifiable list of ports
	 */
	public static List<Port> localList() throws IOException {
		return parseList(SEManage.execSemanage("port", "--noheading", "--list", "--locallist").getStdout());
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
