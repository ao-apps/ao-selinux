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

import com.aoindustries.lang.NullArgumentException;
import com.aoindustries.util.ComparatorUtils;
import com.aoindustries.util.WrappedException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A {@link Port} is a non-overlapping mapping from (protocol, port-range) to SELinux type.
 * Wraps functions of the <code>semanage port</code> commands.
 * <p>
 * This API hides the complexity of the interactions between default policy and local modifications.
 * Instead, it presents the union of both as a single mapping of ports to SELinux types.
 * This means supporting things like punching holes in default policy ranges when only part of the range
 * is overridden by local policy, and also choosing to "modify" or "add" a port based on whether is
 * an exact match or partial overlap with default policy.
 * </p>
 * <p>
 * Port mappings are across all IP addresses on a server.  Thus it is impossible, for example,
 * to have Apache listening on port 12345/tcp on one IP address while SSH listens on the same port 12345/tcp
 * on a different IP address, even though both of these are custom ports and would not seem to be in conflict
 * since on different IP addresses.  By detecting local policy conflicts,
 * the {@link #configure(java.util.Set, java.lang.String) port configuration} catches these
 * conflicts instead of letting two services stomp on one another.
 * </p>
 * <p>
 * TODO: Make a main method to this as command line interface, with a set of commands?
 *       Overkill? commands -&gt; Java API -&gt; semanage -&gt; python API
 * </p>
 *
 * @author  AO Industries, Inc.
 */
public class Port implements Comparable<Port> {

	private static final Logger logger = Logger.getLogger(Port.class.getName());

	public static final int MIN_PORT = 1;
	public static final int MAX_PORT = 65535;

	private static final Pattern listPattern = Pattern.compile("^(\\S+)\\s+(\\S+)\\s+(\\S.*)$");

	/**
	 * Default unreserved port ranges determined from <code>sepolicy network -p ...</code>:
	 * <ol>
	 * <li>tcp/udp: 1-511: reserved_port_t</li>
	 * <li>tcp/udp: 512-1023: hi_reserved_port_t</li>
	 * <li>tcp/udp: 1024-32767: unreserved_port_t</li>
	 * <li>tcp/udp: 32768-61000: ephemeral_port_t</li>
	 * <li>tcp/udp: 61001-65535: unreserved_port_t</li>
	 * </ol>
	 */
	private static final SortedMap<Port, String> defaultPolicyExtensions;
	static {
		SortedMap<Port, String> newMap = new TreeMap<Port, String>();
		// tcp/udp: 1-511: reserved_port_t
		newMap.put(new Port(Protocol.tcp, 1, 511), "reserved_port_t");
		newMap.put(new Port(Protocol.udp, 1, 511), "reserved_port_t");
		// tcp/udp: 512-1023: hi_reserved_port_t
		newMap.put(new Port(Protocol.tcp, 512, 1023), "hi_reserved_port_t");
		newMap.put(new Port(Protocol.udp, 512, 1023), "hi_reserved_port_t");
		// tcp/udp: 1024-32767: unreserved_port_t
		newMap.put(new Port(Protocol.tcp, 1024, 32767), "unreserved_port_t");
		newMap.put(new Port(Protocol.udp, 1024, 32767), "unreserved_port_t");
		// tcp/udp: 32768-61000: ephemeral_port_t
		newMap.put(new Port(Protocol.tcp, 32768, 61000), "ephemeral_port_t");
		newMap.put(new Port(Protocol.udp, 32768, 61000), "ephemeral_port_t");
		// tcp/udp: 61001-65535: unreserved_port_t
		newMap.put(new Port(Protocol.tcp, 61001, 65535), "unreserved_port_t");
		newMap.put(new Port(Protocol.udp, 61001, 65535), "unreserved_port_t");
		assert assertNoOverlaps(newMap);
		defaultPolicyExtensions = Collections.unmodifiableSortedMap(newMap);
	}

	private static final String EOL = System.getProperty("line.separator");

	/**
	 * Adds a port to a set of ports while checking for overlapping already in set.
	 *
	 * @throws  IllegalStateException  if overlap found and set not modified.
	 */
	/* TODO: Unused?
	static void addCheckOverlap(Set<Port> ports, Port newPort) throws IllegalStateException {
		// Look for overlap first
		for(Port port : ports) {
			if(port.overlaps(newPort)) throw new IllegalStateException("Overlapping ports detected: " + port + " and " + newPort);
		}
		if(!ports.add(newPort)) throw new AssertionError("Duplicate item in set without overlap detected");
	}*/

	/**
	 * Searches for any overlapping port ranges in the given set.
	 *
	 * @return  The modifiable set of any port ranges involved in an overlap or an empty set if none overlapping.
	 *
	 * @implNote This implementation is probably not the best regarding computational complexity, but is a simple implementation.
	 */
	static SortedSet<Port> findOverlaps(Iterable<? extends Port> ports) {
		SortedSet<Port> overlaps = new TreeSet<Port>();
		for(Port p1 : ports) {
			for(Port p2 : ports) {
				if(p1 != p2 && p1.overlaps(p2)) {
					overlaps.add(p1);
					overlaps.add(p2);
				}
			}
		}
		return overlaps;
	}

	/**
	 * Gets a full line-by-line dump of the policy.
	 */
	private static <T extends Appendable> T dumpPolicy(SortedMap<? extends Port, String> policy, T out) throws IOException {
		for(Map.Entry<? extends Port, String> entry : policy.entrySet()) {
			out
				.append(entry.getKey().toString())
				.append('=')
				.append(entry.getValue())
				.append(EOL);
		}
		return out;
	}

	/**
	 * Gets a full line-by-line dump of the policy.
	 */
	private static String dumpPolicy(String firstLine, SortedMap<? extends Port, String> policy) {
		try {
			return dumpPolicy(
				policy,
				new StringBuilder()
					.append(firstLine)
					.append(EOL)
			).toString();
		} catch(IOException e) {
			AssertionError ae = new AssertionError("Should not happen on StringBuilder");
			ae.initCause(e);
			throw ae;
		}
	}

	/**
	 * Checks that there are not overlaps.
	 *
	 * @return  {@code true} if no overlaps found
	 *
	 * @throws AssertionError if any overlap found
	 */
	private static boolean assertNoOverlaps(SortedMap<? extends Port, String> policy) throws AssertionError {
		SortedSet<Port> overlaps = findOverlaps(policy.keySet());
		if(!overlaps.isEmpty()) {
			if(logger.isLoggable(Level.FINE)) {
				logger.fine(dumpPolicy("Policy with overlapping ports: " + overlaps, policy));
			}
			throw new AssertionError("Ports overlap: " + overlaps);
		}
		return true;
	}

	/**
	 * Checks that there are not overlaps.
	 *
	 * @return  {@code true} if no overlaps found
	 *
	 * @throws AssertionError if any overlap found
	 */
	private static boolean assertNoOverlaps(SortedSet<? extends Port> ports) throws AssertionError {
		SortedSet<Port> overlaps = findOverlaps(ports);
		if(!overlaps.isEmpty()) throw new AssertionError("Ports overlap: " + ports);
		return true;
	}

	/**
	 * Combines any adjacent port numbers, within the same protocol, into fewer objects.
	 * For example, the following would be combined:
	 * <ul>
	 * <li>80-81, 82 -&gt; 80-82</li>
	 * <li>80, 81 -&gt; 80-81</li>
	 * <li>65, 80, 81-82, 84, 85-90, 91, 92-95 -&gt; 65, 80-82, 84-95</li>
	 * </ul>
	 *
	 * @return the modifiable map of coalesced port ranges.
	 */
	private static SortedMap<Port, String> coalesce(SortedMap<? extends Port, String> policy) {
		assert assertNoOverlaps(policy);
		SortedMap<Port, String> result = new TreeMap<Port, String>();
		// Because the ports are non-overlapping and sorted, this can be done in one pass per protocol
		for(Protocol protocol : Protocol.values()) {
			Port lastPort = null;
			String lastType = null;
			for(Map.Entry<? extends Port, String> entry : policy.entrySet()) {
				Port port = entry.getKey();
				if(protocol == port.getProtocol()) {
					String type = entry.getValue();
					if(
						lastPort != null
						&& (lastPort.getTo() + 1) == port.getFrom()
						&& type.equals(lastType)
					) {
						result.remove(lastPort);
						port = new Port(protocol, lastPort.getFrom(), port.getTo());
					}
					result.put(port, type);
					lastPort = port;
					lastType = type;
				}
			}
		}
		assert assertNoOverlaps(result);
		return result;
	}

	/**
	 * Coalesce for port sets.
	 *
	 * @see  #coalesce(java.util.SortedMap)
	 *
	 * @return the modifiable set of coalesced port ranges.
	 */
	private static SortedSet<Port> coalesce(SortedSet<? extends Port> ports) {
		assert assertNoOverlaps(ports);
		SortedSet<Port> result = new TreeSet<Port>();
		// Because the ports are non-overlapping and sorted, this can be done in one pass per protocol
		for(Protocol protocol : Protocol.values()) {
			Port lastPort = null;
			for(Port port : ports) {
				if(protocol == port.getProtocol()) {
					if(
						lastPort != null
						&& (lastPort.getTo() + 1) == port.getFrom()
					) {
						result.remove(lastPort);
						port = new Port(protocol, lastPort.getFrom(), port.getTo());
					}
					result.add(port);
					lastPort = port;
				}
			}
		}
		assert assertNoOverlaps(result);
		return result;
	}

	/**
	 * Parses the output of <code>semanage port --noheading --list</code>.
	 * Adjacent ports are not coalesced.
	 *
	 * @param  stdout  The raw output from the <code>semanage</code> command.
	 * @param  ignore  An optional set of ports to ignore from the list.
	 *                 This is used to remove the local policy from the overall list to obtain the default policy.
	 *
	 * @return  the unmodifiable mapping of non-overlapping port ranges to SELinux type.
	 */
	static SortedMap<Port,String> parseList(String stdout, Map<? extends Port,? extends String> ignore) throws IOException {
		SortedMap<Port, String> ports = new TreeMap<Port, String>();
		BufferedReader in = new BufferedReader(new StringReader(stdout));
		String line;
		while((line = in.readLine()) != null) {
			try {
				Matcher matcher = listPattern.matcher(line);
				if(!matcher.find()) throw new IOException("Line not matched: " + line);
				assert matcher.groupCount() == 3;
				String type = matcher.group(1).intern();
				Protocol protocol = Protocol.valueOf(matcher.group(2));
				boolean foundPortRange = false;
				StringTokenizer tokens = new StringTokenizer(matcher.group(3), ", ");
				while(tokens.hasMoreTokens()) {
					foundPortRange = true;
					Port port;
					{
						String token = tokens.nextToken();
						int hyphenPos = token.indexOf('-');
						if(hyphenPos == -1) {
							port = new Port(
								protocol,
								Integer.parseInt(token)
							);
						} else {
							port = new Port(
								protocol,
								Integer.parseInt(token.substring(0, hyphenPos)),
								Integer.parseInt(token.substring(hyphenPos + 1))
							);
						}
					}
					if(ignore == null || !type.equals(ignore.get(port))) {
						String existingType = ports.put(port, type);
						if(existingType != null) throw new IllegalStateException("Duplicate types on same port (" + port + "): " + existingType + " and " + type);
					}
				}
				if(!foundPortRange) throw new IOException("No port numbers found: " + line);
			} catch(IllegalStateException e) {
				throw new WrappedException("line = " + line, e);
			}
		}
		return Collections.unmodifiableSortedMap(ports);
	}

	/**
	 * Gets the local policy.
	 * Adjacent ports are not coalesced.
	 *
	 * @return  the unmodifiable mapping of non-overlapping port ranges to SELinux type.
	 */
	private static SortedMap<Port,String> getLocalPolicy() throws IOException {
		return parseLocalPolicy(SEManage.execSemanage("port", "--noheading", "--list", "--locallist").getStdout());
	}

	/**
	 * Parses the local policy from the provided string.
	 * Adjacent ports are not coalesced.
	 *
	 * @return  the unmodifiable mapping of non-overlapping port ranges to SELinux type.
	 */
	static SortedMap<Port,String> parseLocalPolicy(String stdout) throws IOException {
		SortedMap<Port,String> localPolicy = parseList(stdout, null);
		if(logger.isLoggable(Level.FINEST)) {
			logger.finest(dumpPolicy("Local Policy:", localPolicy));
		}
		assert assertNoOverlaps(localPolicy);
		return localPolicy;
	}

	/**
	 * Gets the default policy without any local policy modifications.
	 * Adjacent ports are not coalesced.
	 * <p>
	 * Knowledge of default policy must be known in order to determine how to configure
	 * the local policy to get the desired results.
	 * </p>
	 * <p>
	 * The local policy must have already been determined, since the default policy is
	 * the result of the <code>semanage port --noheading --list</code> minus the local policy.
	 * </p>
	 *
	 * @return  the unmodifiable mapping of possibly overlapping port ranges to SELinux type.
	 */
	private static SortedMap<Port,String> getDefaultPolicy(SortedMap<Port,String> localPolicy) throws IOException {
		return parseDefaultPolicy(SEManage.execSemanage("port", "--noheading", "--list").getStdout(), localPolicy);
	}

	/**
	 * Parses the default policy from the provided string.
	 * Adjacent ports are not coalesced.
	 *
	 * @return  the unmodifiable mapping of possibly overlapping port ranges to SELinux type.
	 */
	static SortedMap<Port,String> parseDefaultPolicy(String stdout, SortedMap<Port,String> localPolicy) throws IOException {
		assert assertNoOverlaps(localPolicy);
		SortedMap<Port, String> defaultPolicy = parseList(stdout, localPolicy);
		if(logger.isLoggable(Level.FINEST)) {
			logger.finest(dumpPolicy("Default Policy:", defaultPolicy));
		}
		return defaultPolicy;
	}

	/**
	 * Covers part of the given policy with the new port mapping.
	 * Existing entries split, modified, or deleted to make room for the new port.
	 * The new entry is not coalesced with existing entries.
	 * Modifies the policy map in-place.
	 */
	private static void overlay(SortedMap<Port, String> policy, Port port, String type) {
		// Update in a single pass, ending iteration is past the port.to
		Iterator<Map.Entry<Port, String>> entryIter = policy.entrySet().iterator();
		Map<Port, String> toAdd = new HashMap<Port, String>();
		while(entryIter.hasNext()) {
			Map.Entry<Port, String> existingEntry = entryIter.next();
			Port existingPort = existingEntry.getKey();
			if(existingPort.getFrom() > port.getTo()) {
				// Past port.to, end iteration
				break;
			}
			if(port.overlaps(existingPort)) {
				// Get value before removing from map, because value of entry will change!
				String existingType = existingEntry.getValue();
				entryIter.remove();
				// Big is split and added
				Port lowerSplit = existingPort.splitBelow(port.getFrom());
				if(lowerSplit != null && toAdd.put(lowerSplit, existingType) != null) throw new AssertionError();
				Port upperSplit = existingPort.splitAbove(port.getTo());
				if(upperSplit != null && toAdd.put(upperSplit, existingType) != null) throw new AssertionError();
			}
		}
		// Add-back all the results of splitting
		policy.putAll(toAdd);
		// Now that there is a hole in the policy port ranges, add the new entry
		if(policy.put(port, type) != null) throw new AssertionError();
	}

	/**
	 * Gets the effective, non-overlapping policy.
	 * Local policy takes precedence over default policy.
	 * <p>
	 * The default policy is extended, as needed, to include coverage for all ports from
	 * 1 to 65535 for both tcp and udp.
	 * </p>
	 * <p>
	 * Within the default policy, more specific ports will split more general ports, such as port
	 * <code>538/tcp=gdomap_port_t</code> splitting
	 * <code>512-1023/tcp=hi_reserved_port_t</code> into two ranges <code>512-537/tcp=hi_reserved_port_t</code>
	 * and <code>539-1023/tcp=hi_reserved_port_t</code>
	 * </p>
	 * <p>
	 * It is an error if any port range of default policy overlaps but is not a subset of another default policy.
	 * For example, it is not allowed to have both "10-20/tcp" and "15-25/tcp" in the default policy (overlap but not subset),
	 * but is acceptable to have both "10-20/tcp" and "15-20/tcp".
	 * </p>
	 * <p>
	 * To give more consistency: adjacent ports of the same SELinux type are automatically
	 * coalesced during list.  For example, 80/tcp and 81/tcp are listed separately in
	 * default policy, but are combined into 80-81/tcp for this view.
	 * </p>
	 *
	 * @return  the unmodifiable mapping of non-overlapping port ranges to SELinux type, covering all ports 1 through 65535 in both tcp and udp, coalesced into minimum entries.
	 */
	public static SortedMap<Port,String> getPolicy() throws IOException {
		SortedMap<Port,String> localPolicy;
		SortedMap<Port,String> defaultPolicy;
		synchronized(SEManage.semanageLock) {
			localPolicy = getLocalPolicy();
			defaultPolicy = getDefaultPolicy(localPolicy);
		}
		return parsePolicy(localPolicy, defaultPolicy);
	}

	/**
	 * @see  #getPolicy()
	 */
	static SortedMap<Port, String> parsePolicy(SortedMap<Port, String> localPolicy, SortedMap<Port, String> defaultPolicy) {
		assert assertNoOverlaps(localPolicy);
		SortedMap<Port, String> policy = new TreeMap<Port, String>();
		// Add defaults to cover all ports 1 through 65535, if not found in provided default policy
		for(Map.Entry<Port, String> extensionEntry : defaultPolicyExtensions.entrySet()) {
			Port port = extensionEntry.getKey();
			if(!defaultPolicy.containsKey(port)) {
				policy.put(port, extensionEntry.getValue());
			}
		}
		assert assertNoOverlaps(policy);
		// Will add default policy in the order from largest ranges to smallest as this seems
		// to be the way SELinux applies overlapping default policies: smaller ranges take precendence
		// over larger ranges.
		SortedMap<Port, String> sortedDefaultPolicy = new TreeMap<Port, String>(
			new Comparator<Port>() {
				/**
				 * Orders by (to-from) desc, protocol asc, from asc, to asc
				 */
				@Override
				public int compare(Port p1, Port p2) {
					// (to-from) desc
					int size1 = p1.getTo() - p1.getFrom();
					int size2 = p2.getTo() - p2.getFrom();
					int diff = ComparatorUtils.compare(size2, size1);
					if(diff != 0) return diff;
					// to asc, from asc
					return p1.compareTo(p2);
				}
			}
		);
		sortedDefaultPolicy.putAll(defaultPolicy);
		// Next, add default policy, splitting any overlapping
		for(Map.Entry<Port, String> defaultEntry : sortedDefaultPolicy.entrySet()) {
			overlay(policy, defaultEntry.getKey(), defaultEntry.getValue());
		}
		assert assertNoOverlaps(policy);
		// Finally, add local policy, removing or splitting any overlapping
		for(Map.Entry<Port, String> localEntry : localPolicy.entrySet()) {
			overlay(policy, localEntry.getKey(), localEntry.getValue());
		}
		// Coalesce
		policy = coalesce(policy);
		assert assertNoOverlaps(policy);
		if(logger.isLoggable(Level.FINEST)) {
			logger.finest(dumpPolicy("Policy:", policy));
		}
		return policy;
	}

	/**
	 * Calls <code>semanage port -a -t <i>type</i> -p <i>protocol</i> <i>port(s)</i></code>.
	 */
	private static void add(Port port, String type) throws IOException {
		if(logger.isLoggable(Level.INFO)) {
			logger.info("Adding SELinux port: " + port + "=" + type);
		}
		SEManage.execSemanage(
			"port", "-a",
			"-t", type,
			"-p", port.getProtocol().toString(),
			port.getPortRange()
		);
	}

	/**
	 * Calls <code>semanage port -m -t <i>type</i> -p <i>protocol</i> <i>port(s)</i></code>.
	 * Modify is used when we need to precisely overlap a default policy entry.
	 * Overlapping, but not same exact from/to, use add.
	 */
	private static void modify(Port port, String type) throws IOException {
		logger.info("Modifying SELinux port: " + port + "=" + type);
		SEManage.execSemanage(
			"port", "-m",
			"-t", type,
			"-p", port.getProtocol().toString(),
			port.getPortRange()
		);
	}

	/**
	 * Calls <code>semanage port -d -t <i>type</i> -p <i>protocol</i> <i>port(s)</i></code>.
	 */
	private static void delete(Port port, String type) throws IOException {
		logger.info("Deleting SELinux port: " + port + "=" + type);
		SEManage.execSemanage(
			"port", "-d",
			"-t", type,
			"-p", port.getProtocol().toString(),
			port.getPortRange()
		);
	}

	/**
	 * Filters a list of ports by SELinux type.
	 *
	 * @return  the modifiable list of ports of the given type
	 */
	/* TODO: Unused?
	public static List<Port> filterByType(Iterable<? extends Port> ports, String type) {
		List<Port> filtered = new ArrayList<Port>();
		for(Port port : ports) {
			if(port.getType().equals(type)) filtered.add(port);
		}
		return filtered;
	}
	 */

	/**
	 * Filters a list of ports by SELinux type and protocol.
	 *
	 * @return  the modifiable list of port numbers of the given type and protocol
	 */
	/* TODO: Unused?
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
	 */

	/**
	 * Configures one SELinux type to have the given set of ports.
	 * This includes the ability to override default policy.
	 * This is the core purpose of this API: Just tell it what you want it
	 * it'll handle the details.
	 * <p>
	 * Before any changes are made, checks for conflicts with any other local policy.
	 * </p>
	 * <p>
	 * TODO: The provided ports are automatically {@link #coalesce(java.util.SortedMap) coalesced}
	 * into the minimum number of port ranges.  For example, if both ports <code>1234/tcp</code>
	 * and <code>1235/tcp</code> are requested, a single local policy of <code>1234-1235/tcp</code>
	 * is generated.
	 * </p>
	 * <p>
	 * TODO: In the first modification pass, adds any entries that are missing.  However,
	 * any conflicting local policy is removed as-needed to allow the addition
	 * of the new entry.
	 * </p>
	 * <p>
	 * TODO: While adding the local policy, there are two interactions with default policy
	 * considered.  First, if the local policy is completely covered by a default policy
	 * entry of the expected type, the local policy entry is not added.  Second, if
	 * the local policy has the same exact port range as an existing policy entry (of
	 * a different type), {@link #modify(com.aoindustries.selinux.Port, java.lang.String)}
	 * will be performed instead of {@link #add(com.aoindustries.selinux.Port, java.lang.String)}
	 * </p>
	 * <p>
	 * TODO: In the second modification pass, any remaining extra local policy entries
	 * for the type are removed.
	 * </p>
	 * <p>
	 * When default policy is not used for by this type, it is left intact
	 * and not overridden to an {@link #defaultPolicyExtensions unreserved type}.
	 * The security benefits of overriding unused default policy is limited.
	 * Leaving the default policy serves two purposes: leaving a more predictable
	 * system and allowing a different SELinux type to override the port(s).
	 * </p>
	 *
	 * @param  ports  The set of all ports that should be set to the given type.
	 *                There must not be any overlap in the provided port ranges.
	 *
	 * @param  type  The SELinux type for the given set of ports.
	 *
	 * @throws  IllegalArgumentException  if any overlapping port numbers found
	 * @throws  IllegalStateException  if detected overlap with local policy of a different type
	 */
	public static void configure(Set<? extends Port> ports, String type) throws IllegalArgumentException, IllegalStateException, IOException {
		// There must not be any overlapping port ranges
		{
			SortedSet<Port> overlaps = findOverlaps(ports);
			if(!overlaps.isEmpty()) {
				throw new IllegalArgumentException("Ports overlap: " + overlaps);
			}
		}
		synchronized(SEManage.semanageLock) {
			// Load local policy
			SortedMap<Port, String> localPolicy = getLocalPolicy();

			// Check for any conflicts with any other local policy
			{
				SortedMap<Port, String> conflicts = new TreeMap<Port, String>();
				for(Port port : ports) {
					int portTo = port.getTo();
					for(Map.Entry<Port, String> localEntry : localPolicy.entrySet()) {
						Port localPort = localEntry.getKey();
						if(localPort.getFrom() > portTo) {
							// Past port.to, end iteration
							break;
						}
						if(port.overlaps(localPort)) {
							String localType = localEntry.getValue();
							if(!type.equals(localType)) {
								conflicts.put(localPort, localType);
							}
						}
					}
				}
				if(!conflicts.isEmpty()) {
					throw new IllegalStateException("Ports (" + ports + ") of type " + type + " conflict with other local policy: " + conflicts);
				}
			}

			// Coalesce the parameters
			SortedSet<Port> coalesced = coalesce(new TreeSet<Port>(ports));

			// TODO: From here
			// Load default policy
			SortedMap<Port, String> defaultPolicy = getDefaultPolicy(localPolicy);

			// Avoid concurrent configuration of ports
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
	private final int from;
	private final int to;

	public Port(Protocol protocol, int port) {
		this(protocol, port, port);
	}

	public Port(Protocol protocol, int from, int to) {
		this.protocol = NullArgumentException.checkNotNull(protocol, "protocol");
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
		return getPortRange() + '/' + protocol;
	}

	@Override
	public boolean equals(Object obj) {
		if(!(obj instanceof Port)) return false;
		Port other = (Port)obj;
		return
			protocol == other.protocol
			&& from == other.from
			&& to == other.to
		;
	}

	@Override
	public int hashCode() {
		int hash = protocol.hashCode();
		hash = hash * 31 + from;
		hash = hash * 31 + to;
		return hash;
	}

	/**
	 * Ordered by from, to, protocol.
	 * The fact that is ordered by "from" is used to break loops, this ordering
	 * must not be changed without adjusting other code.
	 *
	 * TODO: Test this ordering by "from" since other code makes this assumption?
	 */
	@Override
	public int compareTo(Port other) {
		// Java 1.8: Use Integer.compare instead
		int diff = ComparatorUtils.compare(from, other.from);
		if(diff != 0) return diff;
		diff = ComparatorUtils.compare(to, other.to);
		if(diff != 0) return diff;
		return protocol.compareTo(other.protocol);
	}

	public Protocol getProtocol() {
		return protocol;
	}

	public int getFrom() {
		return from;
	}

	public int getTo() {
		return to;
	}

	/**
	 * Gets a string representation of the port range, appropriate for passing to <code>semanage</code>.
	 */
	public String getPortRange() {
		if(from == to) return Integer.toString(from);
		else return Integer.toString(from) + '-' + Integer.toString(to);
	}

	/**
	 * Checks if this port range contains the given port.
	 */
	/* TODO: Unused?
	public boolean hasPort(Protocol protocol, int port) {
		return
			protocol == this.protocol
			&& port >= from
			&& port <= to
		;
	}
	 */

	/**
	 * Checks if this port range has any of the given ports.
	 */
	/* TODO: Unused?
	public boolean hasPort(Protocol protocol, Iterable<? extends Integer> ports) {
		for(int port : ports) {
			if(hasPort(protocol, port)) return true;
		}
		return false;
	}
	 */

	/**
	 * Checks if this port is of the same protocol and overlaps the given port range.
	 */
	public boolean overlaps(Port other) {
		// See http://stackoverflow.com/questions/3269434/whats-the-most-efficient-way-to-test-two-integer-ranges-for-overlap
		return
			protocol == other.protocol
			&& from <= other.to
			&& other.from <= to
		;
	}

	/**
	 * Checks if this port overlaps any of the given port ranges.
	 */
	/* TODO: Unused?
	public boolean overlaps(Iterable<? extends Port> ports) {
		for(Port other : ports) {
			if(overlaps(other)) return true;
		}
		return false;
	}
	 */

	/**
	 * Checks if this port is a subrange of the other port.
	 * If the same range, it is considered a subrange.
	 */
	/* TODO: Unused?
	boolean isSubRangeOf(Port other) {
		return
			protocol == other.protocol
			&& from >= other.from
			&& to <= other.to
		;
	}
	 */

	/**
	 * Gets the part of this port range below the given port or {@code null} if none.
	 */
	Port splitBelow(int below) {
		int newTo = Math.min(to, below - 1);
		if(newTo >= from) return new Port(protocol, from, newTo);
		else return null;
	}

	/**
	 * Gets the part of this port range above the given port or {@code null} if none.
	 */
	Port splitAbove(int above) {
		int newFrom = Math.max(from, above + 1);
		if(newFrom <= to) return new Port(protocol, newFrom, to);
		else return null;
	}
}
