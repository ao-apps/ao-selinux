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
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A {@link Port} is a non-overlapping mapping from (protocol, port-range) to SELinux type.
 * Wraps functions of the <code>semanage port</code> commands.
 * <p>
 * Ports that are part of the default policy may not be removed, but their
 * effective type may be modified with <code>semanage port -m ...</code>.
 * Ports may be added that overlap those of the default policy, but if they exactly
 * match the port range of the default policy, then it must modify instead of add.
 * Locally defined ports override those of the default policy.  When there are overlaps
 * between local modifications and default policy, only the non-overlapped part of the policy
 * is in effect.
 * </p>
 * <p>
 * TODO: This API hides the complexity of the interactions between default policy and local modifications.
 * Instead, it presents the union of both as a single mapping of ports to SELinux types.
 * This means supporting things like punching holes in default policy ranges when only part of the range
 * is overridden by local policy, and also choosing to "modify" or "add" a port based on whether is
 * an exact match or partial overlap with default policy.
 * </p>
 * <p>
 * TODO: Port mappings are across all IP addresses on a server.  Thus it is impossible, for example,
 * to have Apache listening on port 12345/tcp on one IP address while SSH listens on the same port 12345/tcp
 * on a different IP address, even though both of these are custom ports and would not seem to be in conflict
 * since on different IP addresses.  The port configuration is careful to catch these conflicts instead of
 * letting two services stomp on one another.
 * </p>
 * <p>
 * TODO: Also, adjacent ports of the same SELinux type are automatically coalesced during list.
 * </p>
 * <p>
 * TODO: Make a main method to this as command line interface, with a set of commands?
 *       Overkill? commands -&gt; Java API -&gt; semanage -&gt; python API
 * </p>
 *
 * TODO: Log changes as INFO level
 * TODO: assert no port overlaps in list
 * TODO: Add more tests
 * TODO: Change instead of list of Port, but mapping if (Protocol,PortRange) -> SELinx type (careful to handle local modifications overriding default policy)
 *
 * @author  AO Industries, Inc.
 */
public class Port implements Comparable<Port> {

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
	public static SortedMap<Port,String> getDefaultPolicy() throws IOException {
		return parseList(SEManage.execSemanage("port", "--noheading", "--list").getStdout());
	}

	/**
	 * Calls <code>semanage port --list</code>.
	 *
	 * @return  the unmodifiable list of ports
	 */
	public static SortedMap<Port,String> getPolicy() throws IOException {
		return parseList(SEManage.execSemanage("port", "--noheading", "--list").getStdout());
	}

	/**
	 * Calls <code>semanage port --list --locallist</code>.
	 *
	 * @return  the unmodifiable list of ports
	 */
	public static SortedMap<Port,String> getLocalPolicy() throws IOException {
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
	 * First any missing port ranges are added while removing any existing conflicting ports.
	 * Then any extra port ranges are removed.
	 * <p>
	 * <code>selinux port -m ...</code> can be used to modify a port provided by the default
	 * policy, but this current implementation will not do so.  Resolving this conflict is
	 * beyond the scope of the current release.
	 * </p>
	 * TODO: Make sure to detect a configuration issue when two different SELinux types are trying to get the same port.  Don't simply bounce back-and-forth on whichever configured last.
	 * TODO: Error if overlaps the existing non-default policy of another SELinux type.
	 * TODO: Error if some other non-default policy has overridden a default policy that we need. (httpd detect if 80 overridden to sshd, for example)
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

	private final Protocol protocol;
	private final PortRange portRange;

	Port(Protocol protocol, PortRange portRange) {
		this.protocol = protocol;
		this.portRange = portRange;
	}

	@Override
	public String toString() {
		return portRange.toString() + '/' + protocol.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if(!(obj instanceof Port)) return false;
		Port other = (Port)obj;
		return
			protocol == other.protocol
			&& portRange.equals(other.portRange)
		;
	}

	@Override
	public int hashCode() {
		return
			protocol.hashCode() * 31
			+ portRange.hashCode()
		;
	}

	/**
	 * Ordered by portRange, protocol
	 */
	@Override
	public int compareTo(Port other) {
		int diff = portRange.compareTo(other.portRange);
		if(diff != 0) return diff;
		return protocol.compareTo(other.protocol);
	}

	public Protocol getProtocol() {
		return protocol;
	}

	public PortRange getPortRange() {
		return portRange;
	}
}
