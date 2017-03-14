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

public class SEManagePortTest {
	
	public SEManagePortTest() {
	}

	private String testData;

	@Before
	public void setUp() throws IOException {
		final String RESOURCE = "semanage-port-noheading-list.txt";
		InputStream resourceIn = SEManagePortTest.class.getResourceAsStream(RESOURCE);
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
				new SEManage.Port(
					"afs3_callback_port_t",
					SEManage.Port.Protocol.tcp,
					Collections.singletonList(new SEManage.Port.PortNumber(7001, 7001))
				),
				// afs3_callback_port_t           udp      7001
				new SEManage.Port(
					"afs3_callback_port_t",
					SEManage.Port.Protocol.udp,
					Collections.singletonList(new SEManage.Port.PortNumber(7001, 7001))
				),
				// afs_fs_port_t                  udp      7000, 7005
				new SEManage.Port(
					"afs_fs_port_t",
					SEManage.Port.Protocol.udp,
					Arrays.asList(
						new SEManage.Port.PortNumber(7000, 7000),
						new SEManage.Port.PortNumber(7005, 7005)
					)
				),
				// amanda_port_t                  tcp      10080-10083
				new SEManage.Port(
					"amanda_port_t",
					SEManage.Port.Protocol.tcp,
					Collections.singletonList(new SEManage.Port.PortNumber(10080, 10083))
				),
				// amanda_port_t                  udp      10080-10082
				new SEManage.Port(
					"amanda_port_t",
					SEManage.Port.Protocol.udp,
					Collections.singletonList(new SEManage.Port.PortNumber(10080, 10082))
				),
				// ssh_port_t                     tcp      22
				new SEManage.Port(
					"ssh_port_t",
					SEManage.Port.Protocol.tcp,
					Collections.singletonList(new SEManage.Port.PortNumber(22, 22))
				),
				// zope_port_t                    tcp      8021
				new SEManage.Port(
					"zope_port_t",
					SEManage.Port.Protocol.tcp,
					Collections.singletonList(new SEManage.Port.PortNumber(8021, 8021))
				)
			),
			SEManage.Port.parseList(testData)
		);
	}
}
