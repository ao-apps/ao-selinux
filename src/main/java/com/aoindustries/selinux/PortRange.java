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

import com.aoindustries.util.ComparatorUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.StringTokenizer;
import java.util.TreeSet;

/**
 * Port numbers may be a single port or a range of ports.
 * When a single port, this will have the same from and to port.
 *
 * @author  AO Industries, Inc.
 */
public class PortRange implements Comparable<PortRange> {

	public static final int MIN_PORT = 1;
	public static final int MAX_PORT = 65535;

	/**
	 * Parses the port number list.
	 *
	 * @return  the unmodifiable list of port numbers
	 */
	// Not private for unit testing
	static List<PortRange> parsePortRanges(String group) throws IOException {
		List<PortRange> portRanges = new ArrayList<PortRange>();
		StringTokenizer tokens = new StringTokenizer(group, ", ");
		while(tokens.hasMoreTokens()) {
			String token = tokens.nextToken();
			int hyphenPos = token.indexOf('-');
			PortRange newPortRange;
			if(hyphenPos == -1) {
				newPortRange = new PortRange(
					Integer.parseInt(token)
				);
			} else {
				newPortRange = new PortRange(
					Integer.parseInt(token.substring(0, hyphenPos)),
					Integer.parseInt(token.substring(hyphenPos + 1))
				);
			}
			portRanges.add(newPortRange);
		}
		if(portRanges.isEmpty()) throw new IOException("No port numbers found: " + group);
		return Collections.unmodifiableList(portRanges);
	}

	/**
	 * Searches for any overlapping port ranges in the given set.
	 *
	 * @return  The modifiable set of any port ranges involved in an overlap or an empty set if none overlapping.
	 *
	 * @implNote This implementation is probably not the best regarding computational complexity, but is a simple implementation.
	 */
	public static SortedSet<PortRange> findOverlaps(Iterable<? extends PortRange> portRanges) {
		SortedSet<PortRange> overlapping = new TreeSet<PortRange>();
		for(PortRange pn1 : portRanges) {
			for(PortRange pn2 : portRanges) {
				if(pn1 != pn2 && pn1.overlaps(pn2)) {
					overlapping.add(pn1);
					overlapping.add(pn2);
				}
			}
		}
		return overlapping;
	}

	/**
	 * Combines any adjacent port numbers into fewer objects.
	 * For example, the following would be combined:
	 * <ul>
	 * <li>80-81, 82 -&gt; 80-82</li>
	 * <li>80, 81 -&gt; 80-81</li>
	 * <li>65, 80, 81-82, 84, 85-90, 91, 92-95 -&gt; 65, 80-82, 84-95</li>
	 * </ul>
	 *
	 * @return the modifiable set of coalesced port ranges.
	 *
	 * @implNote This implementation is probably not the best regarding computational complexity, but is a simple implementation.
	 */
	public static SortedSet<PortRange> coalesce(Set<? extends PortRange> portRanges) {
		SortedSet<PortRange> result = new TreeSet<PortRange>(portRanges);
		// Repeat until nothing changed
		MODIFIED_LOOP :
		while(true) {
			for(PortRange pn1 : result) {
				for(PortRange pn2 : result) {
					if(pn1 != pn2) {
						PortRange coalesced = pn1.coalesce(pn2);
						if(coalesced != null) {
							result.remove(pn1);
							result.remove(pn2);
							result.add(coalesced);
							continue MODIFIED_LOOP;
						}
					}
				}
			}
			break;
		}
		assert findOverlaps(result).isEmpty();
		return result;
	}

	private final int from;
	private final int to;

	public PortRange(int port) {
		this(port, port);
	}

	public PortRange(int from, int to) {
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
		if(!(obj instanceof PortRange)) return false;
		PortRange other = (PortRange)obj;
		return
			from == other.from
			&& to == other.to
		;
	}

	@Override
	public int hashCode() {
		return from * 31 + to;
	}

	/**
	 * Ordered by from, to.
	 */
	@Override
	public int compareTo(PortRange other) {
		// Java 1.8: Use Integer.compare instead
		int diff = ComparatorUtils.compare(from, other.from);
		if(diff != 0) return diff;
		return ComparatorUtils.compare(to, other.to);
	}

	public int getFrom() {
		return from;
	}

	public int getTo() {
		return to;
	}

	/**
	 * Checks if this port range contains the given port.
	 */
	public boolean hasPort(int port) {
		return port >= from && port <= to;
	}

	/**
	 * Checks if this port range has any of the given ports.
	 */
	public boolean hasPort(Iterable<? extends Integer> ports) {
		for(int port : ports) {
			if(hasPort(port)) return true;
		}
		return false;
	}

	/**
	 * Checks if this port range overlaps the given port range.
	 */
	public boolean overlaps(PortRange other) {
		// See http://stackoverflow.com/questions/3269434/whats-the-most-efficient-way-to-test-two-integer-ranges-for-overlap
		return from <= other.to && other.from <= to;
	}

	/**
	 * Checks if this port range overlaps any of the given port ranges.
	 */
	public boolean overlaps(Iterable<? extends PortRange> portRanges) {
		for(PortRange other : portRanges) {
			if(overlaps(other)) return true;
		}
		return false;
	}

	/**
	 * Combines this port range with the given port range if they are adjacent.
	 *
	 * @return  The combined range or {@code null} if they are not adjacent.
	 */
	public PortRange coalesce(PortRange other) {
		if(to == (other.from - 1)) {
			// This is immediately before the other
			return new PortRange(from, other.to);
		} else if(from == (other.to + 1)) {
			// This is immediately after the other
			return new PortRange(other.from, to);
		} else {
			return null;
		}
	}
}
