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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Port numbers may be a single port or a range of ports.
 * When a single port, this will have the same from and to port.
 *
 * @author  AO Industries, Inc.
 */
public class PortNumber {

	public static final int MIN_PORT = 1;
	public static final int MAX_PORT = 65535;

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
