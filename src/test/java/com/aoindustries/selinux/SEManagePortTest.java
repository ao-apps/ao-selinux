package com.aoindustries.selinux;

import com.aoindustries.io.IoUtils;
import com.aoindustries.net.IPortRange;
import com.aoindustries.net.Port;
import com.aoindustries.net.PortRange;
import com.aoindustries.net.Protocol;
import com.aoindustries.nio.charset.Charsets;
import com.aoindustries.util.AoCollections;
import com.aoindustries.validation.ValidationException;
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;

// TODO: Move these these to ao-net-types as appropriate
public class SEManagePortTest {
	
	private static String loadResource(String resource) throws IOException {
		InputStream resourceIn = SEManagePortTest.class.getResourceAsStream(resource);
		if(resourceIn == null) throw new IOException("Resource not found: " + resource);
		Reader in = new InputStreamReader(resourceIn, Charsets.UTF_8);
		try {
			return IoUtils.readFully(in);
		} finally {
			in.close();
		}
	}

	public SEManagePortTest() {
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
	public void testFindOverlaps1() throws ValidationException {
		assertEquals(
			AoCollections.emptySortedSet(),
			SEManagePort.findOverlaps(
				Arrays.asList(
					Port.valueOf(10, Protocol.TCP),
					Port.valueOf(10, Protocol.UDP)
				)
			)
		);
	}

	@Test
	public void testFindOverlaps2() throws ValidationException {
		assertEquals(
			AoCollections.singletonSortedSet(
				Port.valueOf(10, Protocol.TCP)
			),
			SEManagePort.findOverlaps(
				Arrays.asList(
					Port.valueOf(10, Protocol.TCP),
					Port.valueOf(10, Protocol.UDP),
					Port.valueOf(10, Protocol.TCP)
				)
			)
		);
	}

	@Test
	public void testFindOverlaps3() throws ValidationException {
		assertEquals(
			new TreeSet<IPortRange>(
				Arrays.asList((IPortRange)
					Port.valueOf(10, Protocol.TCP),
					PortRange.valueOf(1, 10, Protocol.TCP)
				)
			),
			SEManagePort.findOverlaps(
				Arrays.asList((IPortRange)
					Port.valueOf(10, Protocol.TCP),
					Port.valueOf(10, Protocol.UDP),
					PortRange.valueOf(1, 10, Protocol.TCP)
				)
			)
		);
	}

	@Test
	public void testParseList() throws IOException, ValidationException {
		SortedMap<IPortRange, String> expected = new TreeMap<IPortRange, String>();
		// afs3_callback_port_t           tcp      7001
		expected.put(Port.valueOf(7001, Protocol.TCP), "afs3_callback_port_t");
		// afs3_callback_port_t           udp      7001
		expected.put(Port.valueOf(7001, Protocol.UDP), "afs3_callback_port_t");
		// afs_fs_port_t                  udp      7000, 7005
		expected.put(Port.valueOf(7000, Protocol.UDP), "afs_fs_port_t");
		expected.put(Port.valueOf(7005, Protocol.UDP), "afs_fs_port_t");
		// amanda_port_t                  tcp      10080-10083
		expected.put(PortRange.valueOf(10080, 10083, Protocol.TCP), "amanda_port_t");
		// amanda_port_t                  udp      10080-10082
		expected.put(PortRange.valueOf(10080, 10082, Protocol.UDP), "amanda_port_t");
		// ssh_port_t                     tcp      22
		expected.put(Port.valueOf(22, Protocol.TCP), "ssh_port_t");
		// zope_port_t                    tcp      8021
		expected.put(Port.valueOf(8021, Protocol.TCP), "zope_port_t");
		assertEquals(
			expected,
			SEManagePort.parseList(testDataSimpleSubset, null)
		);
	}

	@Test
	public void testParseLocalPolicy() throws IOException, ValidationException {
		SortedMap<IPortRange, String> expected = new TreeMap<IPortRange, String>();
		// ssh_port_t                     tcp      8991, 8008
		expected.put(Port.valueOf(8991, Protocol.TCP), "ssh_port_t");
		expected.put(Port.valueOf(8008, Protocol.TCP), "ssh_port_t");
		assertEquals(
			expected,
			SEManagePort.parseLocalPolicy(testDataLocalWithModified8008)
		);
	}

	@Test
	public void testParseLocalPolicyNoOverlap() throws IOException {
		assertEquals(
			AoCollections.emptySortedSet(),
			SEManagePort.findOverlaps(SEManagePort.parseLocalPolicy(testDataLocalWithModified8008).keySet())
		);
	}

	@Test
	public void testParseDefaultPolicy() throws IOException, ValidationException {
		SortedMap<IPortRange, String> localPolicy = SEManagePort.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<IPortRange, String> defaultPolicy = SEManagePort.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		// Make sure the default policy is used for port 8080
		assertEquals(
			"http_port_t",
			defaultPolicy.get(Port.valueOf(8008, Protocol.TCP))
		);
	}

	@Test
	public void testParsePolicy() throws IOException, ValidationException {
		SortedMap<IPortRange, String> localPolicy = SEManagePort.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<IPortRange, String> defaultPolicy = SEManagePort.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		SortedMap<IPortRange, String> policy = SEManagePort.parsePolicy(localPolicy, defaultPolicy);
		// Make sure the local policy is used for port 8080
		assertEquals(
			"ssh_port_t",
			policy.get(Port.valueOf(8008, Protocol.TCP))
		);
	}

	@Test
	public void testGetPolicyCoverFullPortRange() throws IOException {
		SortedMap<IPortRange, String> localPolicy = SEManagePort.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<IPortRange, String> defaultPolicy = SEManagePort.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		SortedMap<IPortRange, String> policy = SEManagePort.parsePolicy(localPolicy, defaultPolicy);
		for(Protocol protocol : new Protocol[] {Protocol.TCP, Protocol.UDP}) {
			IPortRange lastPortRange = null;
			for(IPortRange portRange : policy.keySet()) {
				if(portRange.getProtocol() == protocol) {
					if(lastPortRange == null) {
						assertEquals(
							"Must start on port 1",
							1,
							portRange.getFrom()
						);
					} else {
						assertEquals(
							"Must be one after last seen",
							lastPortRange.getTo() + 1,
							portRange.getFrom()
						);
					}
					lastPortRange = portRange;
				}
			}
			assertNotNull(lastPortRange);
			assertEquals(
				"Must end on port 65535",
				65535,
				lastPortRange.getTo()
			);
		}
	}

	@Test
	public void testGetPolicyCoalesced() throws IOException, ValidationException {
		SortedMap<IPortRange, String> localPolicy = SEManagePort.parseLocalPolicy(testDataLocalWithModified8008);
		SortedMap<IPortRange, String> defaultPolicy = SEManagePort.parseDefaultPolicy(testDataFullWithModified8008, localPolicy);
		SortedMap<IPortRange, String> policy = SEManagePort.parsePolicy(localPolicy, defaultPolicy);
		for(Protocol protocol : new Protocol[] {Protocol.TCP, Protocol.UDP}) {
			IPortRange lastPortRange = null;
			String lastType = null;
			for(Map.Entry<IPortRange, String> entry: policy.entrySet()) {
				IPortRange portRange = entry.getKey();
				if(portRange.getProtocol() == protocol) {
					String type = entry.getValue();
					if(lastPortRange != null) {
						assertNotEquals(
							"Adjacent ports must be of different types when properly coalesced (" + lastPortRange +", " + portRange + ")",
							lastType,
							type
						);
					}
					lastPortRange = portRange;
					lastType = type;
				}
			}
			assertNotNull(lastPortRange);
			assertNotNull(lastType);
		}
		assertEquals(
			"saphostctrl_port_t",
			policy.get(PortRange.valueOf(1128, 1129, Protocol.TCP))
		);
	}

	@Test
	public void testToString1() throws ValidationException {
		assertEquals(
			"1-65535/UDP",
			PortRange.valueOf(1, 65535, Protocol.UDP).toString()
		);
	}

	@Test
	public void testToString2() throws ValidationException {
		assertEquals(
			"167/TCP",
			Port.valueOf(167, Protocol.TCP).toString()
		);
	}

	@Test
	public void testToString3() throws ValidationException {
		assertEquals(
			"67/UDP",
			Port.valueOf(67, Protocol.UDP).toString()
		);
	}

	public void testPortRangeMinFrom() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			PortRange.valueOf(1, 10, Protocol.TCP)
		);
	}

	public void testPortRangeMaxFrom() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			Port.valueOf(65535, Protocol.TCP)
		);
	}

	@Test(expected = ValidationException.class)
	public void testPortRangeLowFrom() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			PortRange.valueOf(0, 10, Protocol.TCP)
		);
	}

	@Test(expected = ValidationException.class)
	public void testPortRangeHighFrom() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			PortRange.valueOf(65536, 10, Protocol.TCP)
		);
	}

	public void testPortRangeMinTo() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			Port.valueOf(1, Protocol.TCP)
		);
	}

	public void testPortRangeMaxTo() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			PortRange.valueOf(10, 65535, Protocol.TCP)
		);
	}

	@Test(expected = ValidationException.class)
	public void testPortRangeLowTo() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			PortRange.valueOf(10, 0, Protocol.TCP)
		);
	}

	@Test(expected = ValidationException.class)
	public void testPortRangeHighTo() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			PortRange.valueOf(10, 65536, Protocol.TCP)
		);
	}

	@Test(expected = ValidationException.class)
	public void testPortRangeFromBiggerTo() throws IOException, ValidationException {
		assertNotNull( // Using this assertion to avoid editor warnings about return value not used
			PortRange.valueOf(10, 1, Protocol.TCP)
		);
	}

	@Test
	public void testCompareTo1() throws ValidationException {
		assertTrue(
			Port.valueOf(1, Protocol.TCP).compareTo(
				Port.valueOf(1, Protocol.TCP)
			)
			== 0
		);
	}

	@Test
	public void testCompareTo2() throws ValidationException {
		assertTrue(
			Port.valueOf(1, Protocol.TCP).compareTo(
				PortRange.valueOf(1, 2, Protocol.TCP)
			)
			< 0
		);
	}

	@Test
	public void testCompareTo3() throws ValidationException {
		assertTrue(
			Port.valueOf(1, Protocol.TCP).compareTo(
				Port.valueOf(1, Protocol.UDP)
			)
			< 0
		);
	}

	@Test
	public void testCompareTo4() throws ValidationException {
		assertTrue(
			"Detected from sorting before to",
			PortRange.valueOf(10, 15, Protocol.TCP).compareTo(
				PortRange.valueOf(11, 14, Protocol.TCP)
			)
			< 0
		);
	}

	@Test
	public void testGetPortRange1() throws ValidationException {
		assertEquals(
			"1-65535",
			SEManagePort.getPortRange(PortRange.valueOf(1, 65535, Protocol.UDP))
		);
	}

	@Test
	public void testGetPortRange2() throws ValidationException {
		assertEquals(
			"167",
			SEManagePort.getPortRange(Port.valueOf(167, Protocol.TCP))
		);
	}

	@Test
	public void testGetPortRange3() throws ValidationException {
		assertEquals(
			"67",
			SEManagePort.getPortRange(Port.valueOf(67, Protocol.UDP))
		);
	}

	@Test
	public void testOverlaps1() throws ValidationException {
		assertTrue(
			Port.valueOf(10, Protocol.UDP).overlaps(
				Port.valueOf(10, Protocol.UDP)
			)
		);
	}

	@Test
	public void testOverlaps2() throws ValidationException {
		assertFalse(
			Port.valueOf(10, Protocol.TCP).overlaps(
				Port.valueOf(10, Protocol.UDP)
			)
		);
	}

	@Test
	public void testOverlaps3() throws ValidationException {
		assertTrue(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				Port.valueOf(10, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps4() throws ValidationException {
		assertTrue(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				Port.valueOf(5, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps5() throws ValidationException {
		assertFalse(
			Port.valueOf(5, Protocol.TCP).overlaps(
				Port.valueOf(11, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps6() throws ValidationException {
		assertFalse(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				Port.valueOf(11, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps7() throws ValidationException {
		assertFalse(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				Port.valueOf(4, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps8() throws ValidationException {
		assertTrue(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				PortRange.valueOf(1, 5, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps9() throws ValidationException {
		assertTrue(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				PortRange.valueOf(10, 15, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps10() throws ValidationException {
		assertFalse(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				PortRange.valueOf(1, 4, Protocol.TCP)
			)
		);
	}

	@Test
	public void testOverlaps11() throws ValidationException {
		assertFalse(
			PortRange.valueOf(5, 10, Protocol.TCP).overlaps(
				PortRange.valueOf(11, 15, Protocol.TCP)
			)
		);
	}
}
