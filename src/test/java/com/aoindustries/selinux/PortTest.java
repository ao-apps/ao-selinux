package com.aoindustries.selinux;

import com.aoindustries.io.IoUtils;
import com.aoindustries.nio.charset.Charsets;
import com.aoindustries.util.AoCollections;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class PortTest {
	
	private static String loadResource(String resource) throws IOException {
		InputStream resourceIn = PortTest.class.getResourceAsStream(resource);
		if(resourceIn == null) throw new IOException("Resource not found: " + resource);
		Reader in = new InputStreamReader(resourceIn, Charsets.UTF_8);
		try {
			return IoUtils.readFully(in);
		} finally {
			in.close();
		}
	}

	public PortTest() {
	}

	private static String testDataSimpleSubset;
	private static String testDataLocalWithModified8008;
	private static String testDataFullWithModified8008;

	@BeforeClass
	public static void setUpClass() throws IOException {
		testDataSimpleSubset = loadResource("semanage-port-noheading-list-simple-subset.txt");
		testDataLocalWithModified8008 = loadResource("semanage-port-noheading-list-local-with-modified-8008.txt");
		testDataFullWithModified8008 = loadResource("semanage-port-noheading-list-full-with-modified-8008.txt");
	}
	
	@AfterClass
	public static void tearDownClass() {
		testDataSimpleSubset = null;
		testDataLocalWithModified8008 = null;
		testDataFullWithModified8008 = null;
	}

	@Test
	public void testFindOverlaps1() {
		assertEquals(
			AoCollections.emptySortedSet(),
			Port.findOverlaps(
				Arrays.asList(
					new Port(Protocol.tcp, 10),
					new Port(Protocol.udp, 10)
				)
			)
		);
	}

	@Test
	public void testFindOverlaps2() {
		assertEquals(
			AoCollections.singletonSortedSet(
				new Port(Protocol.tcp, 10)
			),
			Port.findOverlaps(
				Arrays.asList(
					new Port(Protocol.tcp, 10),
					new Port(Protocol.udp, 10),
					new Port(Protocol.tcp, 10)
				)
			)
		);
	}

	@Test
	public void testFindOverlaps3() {
		assertEquals(
			new TreeSet<Port>(
				Arrays.asList(
					new Port(Protocol.tcp, 10),
					new Port(Protocol.tcp, 1, 10)
				)
			),
			Port.findOverlaps(
				Arrays.asList(
					new Port(Protocol.tcp, 10),
					new Port(Protocol.udp, 10),
					new Port(Protocol.tcp, 1, 10)
				)
			)
		);
	}

	@Test
	public void testParseList() throws IOException {
		SortedMap<Port, String> expected = new TreeMap<Port, String>();
		// afs3_callback_port_t           tcp      7001
		expected.put(new Port(Protocol.tcp, 7001), "afs3_callback_port_t");
		// afs3_callback_port_t           udp      7001
		expected.put(new Port(Protocol.udp, 7001), "afs3_callback_port_t");
		// afs_fs_port_t                  udp      7000, 7005
		expected.put(new Port(Protocol.udp, 7000), "afs_fs_port_t");
		expected.put(new Port(Protocol.udp, 7005), "afs_fs_port_t");
		// amanda_port_t                  tcp      10080-10083
		expected.put(new Port(Protocol.tcp, 10080, 10083), "amanda_port_t");
		// amanda_port_t                  udp      10080-10082
		expected.put(new Port(Protocol.udp, 10080, 10082), "amanda_port_t");
		// ssh_port_t                     tcp      22
		expected.put(new Port(Protocol.tcp, 22), "ssh_port_t");
		// zope_port_t                    tcp      8021
		expected.put(new Port(Protocol.tcp, 8021), "zope_port_t");
		assertEquals(
			expected,
			Port.parseList(testDataSimpleSubset, null)
		);
	}

	@Test
	public void testParseLocalPolicy() throws IOException {
		SortedMap<Port, String> expected = new TreeMap<Port, String>();
		// ssh_port_t                     tcp      8991, 8008
		expected.put(new Port(Protocol.tcp, 8991), "ssh_port_t");
		expected.put(new Port(Protocol.tcp, 8008), "ssh_port_t");
		assertEquals(
			expected,
			Port.parseLocalPolicy(testDataLocalWithModified8008)
		);
	}

	@Test
	public void testParseLocalPolicyNoOverlap() throws IOException {
		assertEquals(
			AoCollections.emptySortedSet(),
			Port.findOverlaps(Port.parseLocalPolicy(testDataLocalWithModified8008).keySet())
		);
	}

	@Test
	public void testParseDefaultPolicy() throws IOException {
		SortedMap<Port, String> localPolicy = Port.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<Port, String> defaultPolicy = Port.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		// Make sure the default policy is used for port 8080
		assertEquals(
			"http_port_t",
			defaultPolicy.get(new Port(Protocol.tcp, 8008))
		);
	}

	@Test
	public void testParsePolicy() throws IOException {
		SortedMap<Port, String> localPolicy = Port.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<Port, String> defaultPolicy = Port.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		SortedMap<Port, String> policy = Port.parsePolicy(localPolicy, defaultPolicy);
		// Make sure the local policy is used for port 8080
		assertEquals(
			"ssh_port_t",
			policy.get(new Port(Protocol.tcp, 8008))
		);
	}

	@Test
	public void testGetPolicyCoverFullPortRange() throws IOException {
		SortedMap<Port, String> localPolicy = Port.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<Port, String> defaultPolicy = Port.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		SortedMap<Port, String> policy = Port.parsePolicy(localPolicy, defaultPolicy);
		for(Protocol protocol : Protocol.values()) {
			Port lastPort = null;
			for(Port port : policy.keySet()) {
				if(port.getProtocol() == protocol) {
					if(lastPort == null) {
						assertEquals(
							"Must start on port 1",
							1,
							port.getFrom()
						);
					} else {
						assertEquals(
							"Must be one after last seen",
							lastPort.getTo() + 1,
							port.getFrom()
						);
					}
					lastPort = port;
				}
			}
			assertNotNull(lastPort);
			assertEquals(
				"Must end on port 65535",
				65535,
				lastPort.getTo()
			);
		}
	}

	@Test
	public void testGetPolicyCoalesced() throws IOException {
		SortedMap<Port, String> localPolicy = Port.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<Port, String> defaultPolicy = Port.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		SortedMap<Port, String> policy = Port.parsePolicy(localPolicy, defaultPolicy);
		for(Protocol protocol : Protocol.values()) {
			Port lastPort = null;
			String lastType = null;
			for(Map.Entry<Port, String> entry: policy.entrySet()) {
				Port port = entry.getKey();
				if(port.getProtocol() == protocol) {
					String type = entry.getValue();
					if(lastPort != null) {
						assertNotEquals(
							"Adjacent ports must be of different types when properly coalesced (" + lastPort +", " + port + ")",
							lastType,
							type
						);
					}
					lastPort = port;
					lastType = type;
				}
			}
			assertNotNull(lastPort);
			assertNotNull(lastType);
		}
		assertEquals(
			"saphostctrl_port_t",
			policy.get(new Port(Protocol.tcp, 1128, 1129))
		);
	}

	public void testPortRangeMinFrom() throws IOException {
		new Port(Protocol.tcp, 1, 10);
	}

	public void testPortRangeMaxFrom() throws IOException {
		new Port(Protocol.tcp, 65535, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeLowFrom() throws IOException {
		new Port(Protocol.tcp, 0, 10);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeHighFrom() throws IOException {
		new Port(Protocol.tcp, 65536, 10);
	}

	public void testPortRangeMinTo() throws IOException {
		new Port(Protocol.tcp, 1, 1);
	}

	public void testPortRangeMaxTo() throws IOException {
		new Port(Protocol.tcp, 10, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeLowTo() throws IOException {
		new Port(Protocol.tcp, 10, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeHighTo() throws IOException {
		new Port(Protocol.tcp, 10, 65536);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeFromBiggerTo() throws IOException {
		new Port(Protocol.tcp, 10, 1);
	}

	@Test
	public void testOverlaps1() {
		assertTrue(
			new Port(Protocol.udp, 10).overlaps(
				new Port(Protocol.udp, 10)
			)
		);
	}

	@Test
	public void testOverlaps2() {
		assertFalse(
			new Port(Protocol.tcp, 10).overlaps(
				new Port(Protocol.udp, 10)
			)
		);
	}

	@Test
	public void testOverlaps3() {
		assertTrue(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 10)
			)
		);
	}

	@Test
	public void testOverlaps4() {
		assertTrue(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 5)
			)
		);
	}

	@Test
	public void testOverlaps5() {
		assertFalse(
			new Port(Protocol.tcp, 5).overlaps(
				new Port(Protocol.tcp, 11)
			)
		);
	}

	@Test
	public void testOverlaps6() {
		assertFalse(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 11)
			)
		);
	}

	@Test
	public void testOverlaps7() {
		assertFalse(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 4)
			)
		);
	}

	@Test
	public void testOverlaps8() {
		assertTrue(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 1, 5)
			)
		);
	}

	@Test
	public void testOverlaps9() {
		assertTrue(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 10, 15)
			)
		);
	}

	@Test
	public void testOverlaps10() {
		assertFalse(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 1, 4)
			)
		);
	}

	@Test
	public void testOverlaps11() {
		assertFalse(
			new Port(Protocol.tcp, 5, 10).overlaps(
				new Port(Protocol.tcp, 11, 15)
			)
		);
	}
}
