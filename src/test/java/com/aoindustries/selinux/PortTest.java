package com.aoindustries.selinux;

import com.aoindustries.io.IoUtils;
import com.aoindustries.nio.charset.Charsets;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.util.Collections;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
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

	private String testDataSimpleSubset;
	// TODO: Test that the overridden port 8008 is showing as ssh_type_t
	private String testDataFullWithModified8008;

	@Before
	public void setUp() throws IOException {
		testDataSimpleSubset = loadResource("semanage-port-noheading-list-simple-subset.txt");
		testDataFullWithModified8008 = loadResource("semanage-port-noheading-list-full-with-modified-8008.txt");
	}
	
	@After
	public void tearDown() {
		testDataSimpleSubset = null;
		testDataFullWithModified8008 = null;
	}
	
	@Test
	public void testParseList() throws IOException {
		assertEquals(
			Arrays.asList(
				// afs3_callback_port_t           tcp      7001
				new Port(
					"afs3_callback_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortRange(7001))
				),
				// afs3_callback_port_t           udp      7001
				new Port(
					"afs3_callback_port_t",
					Protocol.udp,
					Collections.singletonList(new PortRange(7001))
				),
				// afs_fs_port_t                  udp      7000, 7005
				new Port(
					"afs_fs_port_t",
					Protocol.udp,
					Arrays.asList(
						new PortRange(7000),
						new PortRange(7005)
					)
				),
				// amanda_port_t                  tcp      10080-10083
				new Port(
					"amanda_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortRange(10080, 10083))
				),
				// amanda_port_t                  udp      10080-10082
				new Port(
					"amanda_port_t",
					Protocol.udp,
					Collections.singletonList(new PortRange(10080, 10082))
				),
				// ssh_port_t                     tcp      22
				new Port(
					"ssh_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortRange(22))
				),
				// zope_port_t                    tcp      8021
				new Port(
					"zope_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortRange(8021))
				)
			),
			Port.parseList(testDataSimpleSubset)
		);
	}
}
