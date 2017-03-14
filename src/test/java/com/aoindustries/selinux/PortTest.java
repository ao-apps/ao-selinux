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
	
	public PortTest() {
	}

	private String testData;

	@Before
	public void setUp() throws IOException {
		final String RESOURCE = "semanage-port-noheading-list.txt";
		InputStream resourceIn = PortTest.class.getResourceAsStream(RESOURCE);
		if(resourceIn == null) throw new IOException("Resource not found: " + RESOURCE);
		Reader in = new InputStreamReader(resourceIn, Charsets.UTF_8);
		try {
			testData = IoUtils.readFully(in);
		} finally {
			in.close();
		}
	}
	
	@After
	public void tearDown() {
		testData = null;
	}
	
	@Test
	public void testParseList() throws IOException {
		assertEquals(
			Arrays.asList(
				// afs3_callback_port_t           tcp      7001
				new Port(
					"afs3_callback_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortNumber(7001))
				),
				// afs3_callback_port_t           udp      7001
				new Port(
					"afs3_callback_port_t",
					Protocol.udp,
					Collections.singletonList(new PortNumber(7001))
				),
				// afs_fs_port_t                  udp      7000, 7005
				new Port(
					"afs_fs_port_t",
					Protocol.udp,
					Arrays.asList(
						new PortNumber(7000),
						new PortNumber(7005)
					)
				),
				// amanda_port_t                  tcp      10080-10083
				new Port(
					"amanda_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortNumber(10080, 10083))
				),
				// amanda_port_t                  udp      10080-10082
				new Port(
					"amanda_port_t",
					Protocol.udp,
					Collections.singletonList(new PortNumber(10080, 10082))
				),
				// ssh_port_t                     tcp      22
				new Port(
					"ssh_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortNumber(22))
				),
				// zope_port_t                    tcp      8021
				new Port(
					"zope_port_t",
					Protocol.tcp,
					Collections.singletonList(new PortNumber(8021))
				)
			),
			Port.parseList(testData)
		);
	}
}
