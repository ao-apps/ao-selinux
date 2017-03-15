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
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wraps functions of the <code>semanage port</code> commands.
 *
 * TODO: Log changes as INFO level
 * TODO: assert no port overlaps in list
 * TODO: Add more tests
 * TODO: Change instead of list of Port, but mapping if (Protocol,PortRange) -> SELinx type
 *
 * @author  AO Industries, Inc.
 */
public class Port {

	private static final Logger logger = Logger.getLogger(Port.class.getName());

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
						PortRange.parsePortRanges(matcher.group(3))
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

	/**
	 * Calls <code>semanage port -a -t <i>type</i> -p <i>protocol</i> <i>port(s)</i></code>.
	 *
	 * Use {@link #configureTypeAndProtocol(java.lang.String, com.aoindustries.selinux.Protocol, java.util.Set)} if port coalescing is desired.
	 */
	public static void add(String type, Protocol protocol, PortRange portRange) throws IOException {
		logger.info("Adding SELinux port: " + type + ", " + protocol + ", " + portRange);
		SEManage.execSemanage(
			"port", "-a",
			"-t", type,
			"-p", protocol.toString(),
			portRange.toString()
		);
	}

	/**
	 * Calls <code>semanage port -d -t <i>type</i> -p <i>protocol</i> <i>port(s)</i></code>.
	 *
	 * Use {@link #configureTypeAndProtocol(java.lang.String, com.aoindustries.selinux.Protocol, java.util.Set)} if port coalescing is desired.
	 */
	public static void delete(String type, Protocol protocol, PortRange portRange) throws IOException {
		logger.info("Deleting SELinux port: " + type + ", " + protocol + ", " + portRange);
		SEManage.execSemanage(
			"port", "-d",
			"-t", type,
			"-p", protocol.toString(),
			portRange.toString()
		);
	}

	/**
	 * Filters a list of ports by SELinux type.
	 *
	 * @return  the modifiable list of ports of the given type
	 */
	public static List<Port> filterByType(Iterable<? extends Port> ports, String type) {
		List<Port> filtered = new ArrayList<Port>();
		for(Port port : ports) {
			if(port.getType().equals(type)) filtered.add(port);
		}
		return filtered;
	}

	/**
	 * Filters a list of ports by SELinux type and protocol.
	 *
	 * @return  the modifiable list of port numbers of the given type and protocol
	 */
	public static List<PortRange> filterByTypeAndProtocol(Iterable<? extends Port> ports, String type, Protocol protocol) {
		List<PortRange> filtered = new ArrayList<PortRange>();
		for(Port port : ports) {
			if(
				port.getType().equals(type)
				&& port.getProtocol() == protocol
			) filtered.addAll(port.getPortRanges());
		}
		return filtered;
	}

	/**
	 * Configures one SELinux type and protocol to have the given set of ports.
	 * Any missing port ranges are added first.
	 * Then any extra port ranges are removed.
	 *
	 * @throws  IllegalArgumentException  if any overlapping port numbers found
	 */
	public static void configureTypeAndProtocol(String type, Protocol protocol, Set<? extends PortRange> portRanges) throws IllegalArgumentException, IOException {
		// There must not be any overlapping port ranges
		SortedSet<PortRange> overlaps = PortRange.findOverlaps(portRanges);
		if(!overlaps.isEmpty()) {
			throw new IllegalArgumentException("Port ranges overlap: " + overlaps);
		}
		// TODO: See if can remove and/or coalesce with default ports
		// TODO: Make sure doesn't overlap ports of other types on the same protocol, IllegalStateException if so
		// Auto-coalesce any adjacent port ranges
		SortedSet<PortRange> coalesced = PortRange.coalesce(portRanges);
		// Avoid concurrent configuration of ports
		synchronized(SEManage.semanageLock) {
			List<PortRange> existingPortRanges = filterByTypeAndProtocol(
				list(),
				type,
				protocol
			);
			// Add any missing ports
			for(PortRange portRange : coalesced) {
				if(!existingPortRanges.contains(portRange)) {
					// Remove any extra ports that overlap the port range we're adding.
					{
						Iterator<PortRange> existingIter = existingPortRanges.iterator();
						while(existingIter.hasNext()) {
							PortRange existing = existingIter.next();
							if(
								!coalesced.contains(existing)
								&& existing.overlaps(portRange)
							) {
								// Remove port number
								delete(type, protocol, existing);
								existingIter.remove();
							}
						}
					}
					add(type, protocol, portRange);
				}
			}
			// Remove any remaining extra ports (those that do not overlap the expected ports)
			for(PortRange existing : existingPortRanges) {
				if(!coalesced.contains(existing)) {
					delete(type, protocol, existing);
				}
			}
		}
	}

	private final String type;
	private final Protocol protocol;
	private final List<PortRange> portRanges;

	Port(
		String type,
		Protocol protocol,
		List<PortRange> portRanges
	) {
		this.type = type;
		this.protocol = protocol;
		this.portRanges = portRanges;
	}

	@Override
	public String toString() {
		return "(" + type + ", " + protocol + ", " + portRanges + ")";
	}

	@Override
	public boolean equals(Object obj) {
		if(!(obj instanceof Port)) return false;
		Port other = (Port)obj;
		return
			type.equals(other.type)
			&& protocol == other.protocol
			&& portRanges.equals(other.portRanges)
		;
	}

	@Override
	public int hashCode() {
		int hash = type.hashCode();
		hash = hash * 31 + protocol.hashCode();
		hash = hash * 31 + portRanges.hashCode();
		return hash;
	}

	public String getType() {
		return type;
	}

	public Protocol getProtocol() {
		return protocol;
	}

	public List<PortRange> getPortRanges() {
		return portRanges;
	}
}
