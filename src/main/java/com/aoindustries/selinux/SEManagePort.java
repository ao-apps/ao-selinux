/*
 * ao-selinux - Java API for managing Security-Enhanced Linux (SELinux).
 * Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  AO Industries, Inc.
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
 * along with ao-selinux.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.aoindustries.selinux;

import com.aoapps.collections.AoCollections;
import com.aoapps.lang.exception.WrappedException;
import com.aoapps.lang.validation.ValidationException;
import com.aoapps.net.IPortRange;
import com.aoapps.net.Port;
import com.aoapps.net.PortRange;
import com.aoapps.net.Protocol;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
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
 * A policy is a non-overlapping mapping from (port-range, protocol) to SELinux type.
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
public final class SEManagePort {

	/** Make no instances. */
	private SEManagePort() {throw new AssertionError();}

	private static final Logger logger = Logger.getLogger(SEManagePort.class.getName());

	private static final Pattern listPattern = Pattern.compile("^(\\S+)\\s+(\\S+)\\s+(\\S.*)$");

	/**
	 * Default unreserved port ranges determined from <code>sepolicy network -p ...</code>.
	 * The following is as of RedHat 7.6:
	 * <ol>
	 * <li>tcp/udp/sctp: 1-511: reserved_port_t</li>
	 * <li>tcp/udp/sctp: 512-1023: hi_reserved_port_t</li>
	 * <li>tcp/udp: 1024-32767: unreserved_port_t</li>
	 * <li>tcp/udp: 32768-61000: ephemeral_port_t</li>
	 * <li>tcp/udp: 61001-65535: unreserved_port_t</li>
	 * <li>sctp: 1024-65535: unreserved_port_t</li>
	 * </ol>
	 */
	private static final SortedMap<PortRange, String> defaultPolicyExtensions;
	static {
		try {
			SortedMap<PortRange, String> newMap = new TreeMap<>();
			// tcp/udp/sctp: 1-511: reserved_port_t
			newMap.put(PortRange.valueOf(1, 511, Protocol.TCP), "reserved_port_t");
			newMap.put(PortRange.valueOf(1, 511, Protocol.UDP), "reserved_port_t");
			newMap.put(PortRange.valueOf(1, 511, Protocol.SCTP), "reserved_port_t");
			// tcp/udp/sctp: 512-1023: hi_reserved_port_t
			newMap.put(PortRange.valueOf(512, 1023, Protocol.TCP), "hi_reserved_port_t");
			newMap.put(PortRange.valueOf(512, 1023, Protocol.UDP), "hi_reserved_port_t");
			newMap.put(PortRange.valueOf(512, 1023, Protocol.SCTP), "hi_reserved_port_t");
			// tcp/udp: 1024-32767: unreserved_port_t
			newMap.put(PortRange.valueOf(1024, 32767, Protocol.TCP), "unreserved_port_t");
			newMap.put(PortRange.valueOf(1024, 32767, Protocol.UDP), "unreserved_port_t");
			// tcp/udp: 32768-61000: ephemeral_port_t
			newMap.put(PortRange.valueOf(32768, 61000, Protocol.TCP), "ephemeral_port_t");
			newMap.put(PortRange.valueOf(32768, 61000, Protocol.UDP), "ephemeral_port_t");
			// tcp/udp: 61001-65535: unreserved_port_t
			newMap.put(PortRange.valueOf(61001, 65535, Protocol.TCP), "unreserved_port_t");
			newMap.put(PortRange.valueOf(61001, 65535, Protocol.UDP), "unreserved_port_t");
			// sctp: 1024-65535: unreserved_port_t
			newMap.put(PortRange.valueOf(1024, 65535, Protocol.SCTP), "unreserved_port_t");
			assert assertNoOverlaps(newMap);
			defaultPolicyExtensions = Collections.unmodifiableSortedMap(newMap);
		} catch(ValidationException e) {
			throw new AssertionError(e);
		}
	}

	private static final String EOL = System.lineSeparator();

	/**
	 * Searches for any overlapping port ranges in the given set.
	 * <p>
	 * <b>Implementation Note:</b><br>
	 * This implementation is probably not the best regarding computational complexity, but is a simple implementation.
	 * </p>
	 *
	 * @return  The modifiable set of any port ranges involved in an overlap or an empty set if none overlapping.
	 */
	static SortedSet<IPortRange> findOverlaps(Iterable<? extends IPortRange> portRanges) {
		List<? extends IPortRange> portRangeList;
		if(portRanges instanceof List) {
			portRangeList = (List<? extends IPortRange>)portRanges;
		} else if(portRanges instanceof Collection) {
			portRangeList = new ArrayList<>((Collection<? extends IPortRange>)portRanges);
		} else {
			List<IPortRange> newList = new ArrayList<>();
			assert portRanges != null;
			for(IPortRange portRange : portRanges) {
				newList.add(portRange);
			}
			portRangeList = newList;
		}
		SortedSet<IPortRange> overlaps = new TreeSet<>();
		int size = portRangeList.size();
		for(int i1 = 0; i1 < size; i1++) {
			IPortRange pr1 = portRangeList.get(i1);
			for(int i2 = 0; i2 < i1; i2++) {
				IPortRange pr2 = portRangeList.get(i2);
				if(pr1.overlaps(pr2)) {
					overlaps.add(pr1);
					overlaps.add(pr2);
				}
			}
		}
		return overlaps;
	}

	/**
	 * Gets a full line-by-line dump of the policy.
	 */
	private static <T extends Appendable> T dumpPolicy(SortedMap<? extends IPortRange, String> policy, T out) throws IOException {
		for(Map.Entry<? extends IPortRange, String> entry : policy.entrySet()) {
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
	private static String dumpPolicy(String firstLine, SortedMap<? extends IPortRange, String> policy) {
		try {
			return dumpPolicy(
				policy,
				new StringBuilder()
					.append(firstLine)
					.append(EOL)
			).toString();
		} catch(IOException e) {
			throw new AssertionError("Should not happen on StringBuilder", e);
		}
	}

	/**
	 * Checks that there are not overlaps.
	 *
	 * @return  {@code true} if no overlaps found
	 *
	 * @throws AssertionError if any overlap found
	 */
	private static boolean assertNoOverlaps(SortedMap<? extends IPortRange, String> policy) throws AssertionError {
		SortedSet<IPortRange> overlaps = findOverlaps(policy.keySet());
		if(!overlaps.isEmpty()) {
			if(logger.isLoggable(Level.FINE)) {
				logger.fine(dumpPolicy("Policy with overlapping ports: " + overlaps, policy));
			}
			throw new AssertionError("Port ranges overlap: " + overlaps);
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
	private static boolean assertNoOverlaps(Iterable<? extends IPortRange> portRanges) throws AssertionError {
		SortedSet<IPortRange> overlaps = findOverlaps(portRanges);
		if(!overlaps.isEmpty()) throw new AssertionError("Port ranges overlap: " + overlaps);
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
	private static SortedMap<IPortRange, String> coalesce(SortedMap<? extends IPortRange, String> policy) {
		// TODO: Is there any ordering that can confuse this, like 1, 3, 2, or 1-3, 2-4, 3-5?
		assert assertNoOverlaps(policy);
		SortedMap<IPortRange, String> result = new TreeMap<>();
		// Because the ports are non-overlapping and sorted, this can be done in one pass per protocol
		for(Protocol protocol : new Protocol[] {Protocol.TCP, Protocol.UDP, Protocol.SCTP}) {
			IPortRange lastPortRange = null;
			String lastType = null;
			for(Map.Entry<? extends IPortRange, String> entry : policy.entrySet()) {
				IPortRange portRange = entry.getKey();
				if(protocol == portRange.getProtocol()) {
					String type = entry.getValue();
					if(
						lastPortRange != null
						&& (lastPortRange.getTo() + 1) == portRange.getFrom()
						&& type.equals(lastType)
					) {
						result.remove(lastPortRange);
						try {
							portRange = IPortRange.valueOf(lastPortRange.getFrom(), portRange.getTo(), protocol);
						} catch(ValidationException e) {
							throw new AssertionError(e);
						}
					}
					result.put(portRange, type);
					lastPortRange = portRange;
					lastType = type;
				}
			}
		}
		assert assertNoOverlaps(result);
		return result;
	}

	/**
	 * Coalesce for sets of port ranges.
	 *
	 * @see  #coalesce(java.util.SortedMap)
	 *
	 * @return the modifiable set of coalesced port ranges.
	 */
	@SuppressWarnings("AssignmentToForLoopParameter")
	private static SortedSet<IPortRange> coalesce(SortedSet<? extends IPortRange> portRanges) {
		// TODO: Is there any ordering that can confuse this, like 1, 3, 2, or 1-3, 2-4, 3-5?
		assert assertNoOverlaps(portRanges);
		SortedSet<IPortRange> result = new TreeSet<>();
		// Because the ports are non-overlapping and sorted, this can be done in one pass per protocol
		for(Protocol protocol : new Protocol[] {Protocol.TCP, Protocol.UDP, Protocol.SCTP}) {
			IPortRange lastPortRange = null;
			for(IPortRange portRange : portRanges) {
				if(protocol == portRange.getProtocol()) {
					if(
						lastPortRange != null
						&& (lastPortRange.getTo() + 1) == portRange.getFrom()
					) {
						result.remove(lastPortRange);
						try {
							portRange = IPortRange.valueOf(lastPortRange.getFrom(), portRange.getTo(), protocol);
						} catch(ValidationException e) {
							throw new AssertionError(e);
						}
					}
					result.add(portRange);
					lastPortRange = portRange;
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
	static SortedMap<IPortRange, String> parseList(String stdout, Map<? extends IPortRange, String> ignore) throws IOException {
		SortedMap<IPortRange, String> portRanges = new TreeMap<>();
		BufferedReader in = new BufferedReader(new StringReader(stdout));
		String line;
		while((line = in.readLine()) != null) {
			try {
				Matcher matcher = listPattern.matcher(line);
				if(!matcher.find()) throw new IOException("Line not matched: " + line);
				assert matcher.groupCount() == 3;
				String type = matcher.group(1).intern();
				Protocol protocol = Protocol.valueOf(matcher.group(2).toUpperCase(Locale.ROOT));
				boolean foundPortRange = false;
				StringTokenizer tokens = new StringTokenizer(matcher.group(3), ", ");
				while(tokens.hasMoreTokens()) {
					foundPortRange = true;
					IPortRange portRange;
					{
						String token = tokens.nextToken();
						int hyphenPos = token.indexOf('-');
						if(hyphenPos == -1) {
							portRange = Port.valueOf(
								Integer.parseInt(token),
								protocol
							);
						} else {
							portRange = PortRange.valueOf(
								Integer.parseInt(token.substring(0, hyphenPos)),
								Integer.parseInt(token.substring(hyphenPos + 1)),
								protocol
							);
						}
					}
					if(ignore == null || !type.equals(ignore.get(portRange))) {
						String existingType = portRanges.put(portRange, type);
						if(existingType != null) throw new IllegalStateException("Duplicate types on same port (" + portRange + "): " + existingType + " and " + type);
					}
				}
				if(!foundPortRange) throw new IOException("No port numbers found: " + line);
			} catch(IllegalStateException | ValidationException e) {
				throw new WrappedException("line = " + line, e);
			}
		}
		return Collections.unmodifiableSortedMap(portRanges);
	}

	/**
	 * Gets the local policy.
	 * Adjacent ports are not coalesced.
	 *
	 * @return  the unmodifiable mapping of non-overlapping port ranges to SELinux type.
	 */
	private static SortedMap<IPortRange, String> getLocalPolicy() throws IOException {
		return parseLocalPolicy(SEManage.execSemanage("port", "--noheading", "--list", "--locallist").getStdout());
	}

	/**
	 * Parses the local policy from the provided string.
	 * Adjacent ports are not coalesced.
	 *
	 * @return  the unmodifiable mapping of non-overlapping port ranges to SELinux type.
	 */
	static SortedMap<IPortRange, String> parseLocalPolicy(String stdout) throws IOException {
		SortedMap<IPortRange, String> localPolicy = parseList(stdout, null);
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
	private static SortedMap<IPortRange, String> getDefaultPolicy(SortedMap<? extends IPortRange, String> localPolicy) throws IOException {
		return parseDefaultPolicy(SEManage.execSemanage("port", "--noheading", "--list").getStdout(), localPolicy);
	}

	/**
	 * Parses the default policy from the provided string.
	 * Adjacent ports are not coalesced.
	 *
	 * @return  the unmodifiable mapping of possibly overlapping port ranges to SELinux type.
	 */
	static SortedMap<IPortRange, String> parseDefaultPolicy(String stdout, SortedMap<? extends IPortRange, String> localPolicy) throws IOException {
		assert assertNoOverlaps(localPolicy);
		SortedMap<IPortRange, String> defaultPolicy = parseList(stdout, localPolicy);
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
	private static void overlay(SortedMap<IPortRange, String> policy, IPortRange portRange, String type) {
		// Update in a single pass, ending iteration is past the port.to
		Iterator<Map.Entry<IPortRange, String>> entryIter = policy.entrySet().iterator();
		Map<IPortRange, String> toAdd = new HashMap<>();
		while(entryIter.hasNext()) {
			// TODO: Is there any ordering that can confuse this, like 1, 3, 2, or 1-3, 2-4, 3-5?
			Map.Entry<IPortRange, String> existingEntry = entryIter.next();
			IPortRange existingPortRange = existingEntry.getKey();
			if(existingPortRange.getFrom() > portRange.getTo()) {
				// Past portRange.to, end iteration
				break;
			}
			if(portRange.overlaps(existingPortRange)) {
				// Get value before removing from map, because value of entry will change!
				String existingType = existingEntry.getValue();
				entryIter.remove();
				// Big is split and added
				IPortRange lowerSplit = existingPortRange.splitBelow(portRange.getFrom());
				if(lowerSplit != null && toAdd.put(lowerSplit, existingType) != null) throw new AssertionError();
				IPortRange upperSplit = existingPortRange.splitAbove(portRange.getTo());
				if(upperSplit != null && toAdd.put(upperSplit, existingType) != null) throw new AssertionError();
			}
		}
		// Add-back all the results of splitting
		policy.putAll(toAdd);
		// Now that there is a hole in the policy port ranges, add the new entry
		if(policy.put(portRange, type) != null) throw new AssertionError();
	}

	/**
	 * Gets the effective, non-overlapping policy.
	 * Local policy takes precedence over default policy.
	 * <p>
	 * The default policy is extended, as needed, to include coverage for all ports from
	 * 1 to 65535 for tcp, udp, and sctp.
	 * </p>
	 * <p>
	 * Within the default policy, more specific ports will split more general ports, such as port
	 * <code>538/tcp=gdomap_port_t</code> splitting
	 * <code>512-1023/tcp=hi_reserved_port_t</code> into two ranges <code>512-537/tcp=hi_reserved_port_t</code>
	 * and <code>539-1023/tcp=hi_reserved_port_t</code>
	 * </p>
	 * <p>
	 * To give more consistency: adjacent ports of the same SELinux type are automatically
	 * coalesced.  For example, 80/tcp and 81/tcp are listed separately in default policy,
	 * but are combined into 80-81/tcp for this view.
	 * </p>
	 *
	 * @return  the unmodifiable mapping of non-overlapping port ranges to SELinux type, covering all ports 1 through 65535 in tcp, udp, and sctp, coalesced into minimum entries.
	 */
	public static SortedMap<IPortRange, String> getPolicy() throws IOException {
		SortedMap<IPortRange, String> localPolicy;
		SortedMap<IPortRange, String> defaultPolicy;
		synchronized(SEManage.semanageLock) {
			localPolicy = getLocalPolicy();
			defaultPolicy = getDefaultPolicy(localPolicy);
		}
		return parsePolicy(localPolicy, defaultPolicy);
	}

	/**
	 * @see  #getPolicy()
	 */
	static SortedMap<IPortRange, String> parsePolicy(SortedMap<? extends IPortRange, String> localPolicy, SortedMap<? extends IPortRange, String> defaultPolicy) {
		assert assertNoOverlaps(localPolicy);
		SortedMap<IPortRange, String> policy = new TreeMap<>();
		// Add defaults to cover all ports 1 through 65535, if not found in provided default policy
		for(Map.Entry<PortRange, String> extensionEntry : defaultPolicyExtensions.entrySet()) {
			PortRange portRange = extensionEntry.getKey();
			if(!defaultPolicy.containsKey(portRange)) {
				policy.put(portRange, extensionEntry.getValue());
			}
		}
		assert assertNoOverlaps(policy);
		// Will add default policy in the order from largest ranges to smallest as this seems
		// to be the way SELinux applies overlapping default policies: smaller ranges take precendence
		// over larger ranges.
		SortedMap<IPortRange, String> sortedDefaultPolicy = new TreeMap<>(
			/**
			 * Orders by (to-from) desc, protocol asc, from asc, to asc
			 */
			(pr1, pr2) -> {
				// (to-from) desc
				int size1 = pr1.getTo() - pr1.getFrom();
				int size2 = pr2.getTo() - pr2.getFrom();
				int diff = Integer.compare(size2, size1);
				if(diff != 0) return diff;
				// to asc, from asc
				return pr1.compareTo(pr2);
			}
		);
		sortedDefaultPolicy.putAll(defaultPolicy);
		// Next, add default policy, splitting any overlapping
		for(Map.Entry<IPortRange, String> defaultEntry : sortedDefaultPolicy.entrySet()) {
			overlay(policy, defaultEntry.getKey(), defaultEntry.getValue());
		}
		assert assertNoOverlaps(policy);
		// Finally, add local policy, removing or splitting any overlapping
		for(Map.Entry<? extends IPortRange, String> localEntry : localPolicy.entrySet()) {
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
	private static void add(IPortRange portRange, String type) throws IOException {
		if(logger.isLoggable(Level.INFO)) {
			logger.info("Adding SELinux port: " + portRange + "=" + type);
		}
		SEManage.execSemanage(
			"port", "-a",
			"-t", type,
			"-p", portRange.getProtocol().name().toLowerCase(Locale.ROOT),
			getPortRange(portRange)
		);
	}

	/**
	 * Calls <code>semanage port -m -t <i>type</i> -p <i>protocol</i> <i>port(s)</i></code>.
	 * Modify is used when we need to precisely overlap a default policy entry.
	 * Overlapping, but not same exact from/to, use add.
	 */
	private static void modify(IPortRange portRange, String type) throws IOException {
		logger.info("Modifying SELinux port: " + portRange + "=" + type);
		SEManage.execSemanage(
			"port", "-m",
			"-t", type,
			"-p", portRange.getProtocol().name().toLowerCase(Locale.ROOT),
			getPortRange(portRange)
		);
	}

	/**
	 * Calls <code>semanage port -d -t <i>type</i> -p <i>protocol</i> <i>port(s)</i></code>.
	 */
	private static void delete(IPortRange portRange, String type) throws IOException {
		logger.info("Deleting SELinux port: " + portRange + "=" + type);
		SEManage.execSemanage(
			"port", "-d",
			"-t", type,
			"-p", portRange.getProtocol().name().toLowerCase(Locale.ROOT),
			getPortRange(portRange)
		);
	}

	/**
	 * Configures one SELinux type to have the given set of ports.
	 * This includes the ability to override default policy.
	 * This is the core purpose of this API: Just tell it what you want and
	 * it will handle the details.
	 * <p>
	 * Before any changes are made, checks for conflicts with any other local policy.
	 * </p>
	 * <p>
	 * The provided ports are automatically {@link #coalesce(java.util.SortedMap) coalesced}
	 * into the minimum number of port ranges.  For example, if both ports <code>1234/tcp</code>
	 * and <code>1235/tcp</code> are requested, a single local policy of <code>1234-1235/tcp</code>
	 * is generated.
	 * </p>
	 * <p>
	 * In the first modification pass, adds any entries that are missing and not
	 * part of the default policy.  However, any conflicting local policy is
	 * removed as-needed to allow the addition of the new entry.
	 * </p>
	 * <p>
	 * While adding the local policy, there are two interactions with default policy
	 * considered.  First, if the local policy precisely matches a default policy
	 * entry of the expected type, the local policy entry is not added.  Second, if
	 * the local policy has the same exact port range as a default policy entry (of
	 * a different type), {@link #modify(com.aoapps.net.IPortRange, java.lang.String)}
	 * will be performed instead of {@link #add(com.aoapps.net.IPortRange, java.lang.String)}.
	 * </p>
	 * <p>
	 * In the second modification pass, any remaining extra local policy entries
	 * for the type are removed, thus freeing these ports for use in the local policy
	 * of other SELinux types.
	 * </p>
	 * <p>
	 * When default policy is not used by this type, it is left intact
	 * and not overridden to an {@link #defaultPolicyExtensions unreserved type}.
	 * The security benefits of overriding unused default policy is limited.
	 * Leaving the default policy serves two purposes: leaving a more predictable
	 * configuration and allowing a different SELinux type to override the port(s)
	 * with their own local policy.
	 * </p>
	 * <p>
	 * <b>Implementation Note:</b><br>
	 * We could punch holes in local policy to avoid overlapping default policy,
	 * but we see no conflict with local policy overlapping default policy.
	 * As an example, if SSH were listening on both ports 22/tcp and 23/tcp,
	 * the current implementation will create a single local policy entry
	 * of 22-23/tcp, which overlaps and is partially redundant with the default
	 * policy of 22/tcp.  One possible benefit of this more complete local
	 * policy is more thorough detection of local policy conflicts.
	 * </p>
	 *
	 * @param  portRanges  The set of all ports that should be set to the given type.
	 *                There must not be any overlap in the provided port ranges.
	 *
	 * @param  type  The SELinux type for the given set of ports.
	 *
	 * @return  if any modification was made to the local policy
	 *
	 * @throws  IllegalArgumentException  if any overlapping port numbers found
	 * @throws  IllegalStateException  if detected overlap with local policy of a different type
	 */
	public static boolean configure(Set<? extends IPortRange> portRanges, String type) throws IllegalArgumentException, IllegalStateException, IOException {
		// There must not be any overlapping port ranges
		{
			SortedSet<IPortRange> overlaps = findOverlaps(portRanges);
			if(!overlaps.isEmpty()) {
				throw new IllegalArgumentException("Port ranges overlap: " + overlaps);
			}
		}
		synchronized(SEManage.semanageLock) {
			// Load local policy
			SortedMap<IPortRange, String> localPolicy = getLocalPolicy();

			// Check for any conflicts with any other local policy
			{
				SortedMap<IPortRange, String> conflicts = new TreeMap<>();
				for(IPortRange portRange : portRanges) {
					int portTo = portRange.getTo();
					for(Map.Entry<IPortRange, String> localEntry : localPolicy.entrySet()) {
						IPortRange localPortRange = localEntry.getKey();
						if(localPortRange.getFrom() > portTo) {
							// Past portRange.to, end iteration
							break;
						}
						if(portRange.overlaps(localPortRange)) {
							String localType = localEntry.getValue();
							if(!type.equals(localType)) {
								conflicts.put(localPortRange, localType);
							}
						}
					}
				}
				if(!conflicts.isEmpty()) {
					throw new IllegalStateException("Port ranges (" + portRanges + ") of type " + type + " conflict with other local policy: " + conflicts);
				}
			}

			// Coalesce the parameters
			SortedSet<IPortRange> coalesced = coalesce(new TreeSet<>(portRanges));

			// Find all local policy for this type
			SortedSet<IPortRange> existingPortRanges = AoCollections.filterByValue(localPolicy, type);

			// Track if modified any policy
			boolean modified = false;

			if(!coalesced.isEmpty()) {
				// Load default policy
				SortedMap<IPortRange, String> defaultPolicy = getDefaultPolicy(localPolicy);

				// Add any missing ports that are not part of the default policy
				for(IPortRange portRange : coalesced) {
					String defaultType = defaultPolicy.get(portRange);
					if(
						// Only add local policy when does not match default policy exactly (both range and type)
						!type.equals(defaultType)
						// Also check if already part of local policy
						&& !existingPortRanges.contains(portRange)
					) {
						// Remove any extra ports that overlap the port range we're adding.
						{
							Iterator<IPortRange> existingIter = existingPortRanges.iterator();
							while(existingIter.hasNext()) {
								IPortRange existing = existingIter.next();
								if(
									!coalesced.contains(existing)
									&& existing.overlaps(portRange)
								) {
									// Remove overlapping extra port
									delete(existing, type);
									existingIter.remove();
								}
							}
						}
						if(defaultType != null) {
							// When precisely overlaps default policy of a different type, have to modify into local policy
							assert !type.equals(defaultType);
							modify(portRange, type);
						} else {
							// Does not align precisely with any default policy, have to add into local policy
							add(portRange, type);
						}
						modified = true;
					}
				}
			}
			// Remove any remaining extra ports (those that do not overlap the expected ports)
			for(IPortRange existing : existingPortRanges) {
				if(!coalesced.contains(existing)) {
					delete(existing, type);
					modified = true;
				}
			}
			return modified;
		}
	}

	/**
	 * Gets a string representation of the port range, appropriate for passing to <code>semanage</code>.
	 */
	static String getPortRange(IPortRange portRange) {
		int from = portRange.getFrom();
		int to = portRange.getTo();
		if(from == to) return Integer.toString(from);
		else return Integer.toString(from) + '-' + Integer.toString(to);
	}
}
