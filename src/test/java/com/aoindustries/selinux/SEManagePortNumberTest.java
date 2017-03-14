package com.aoindustries.selinux;

import java.io.IOException;
import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class SEManagePortNumberTest {
	
	public SEManagePortNumberTest() {
	}

	@Test
	public void testParsePortNumbers1() throws IOException {
		assertEquals(
			Arrays.asList(new SEManage.Port.PortNumber(7001, 7001)),
			SEManage.Port.parsePortNumbers("7001")
		);
	}

	@Test
	public void testParsePortNumbers2() throws IOException {
		assertEquals(
			Arrays.asList(
				new SEManage.Port.PortNumber(7000, 7000),
				new SEManage.Port.PortNumber(7005, 7005)
			),
			SEManage.Port.parsePortNumbers("7000, 7005")
		);
	}

	@Test
	public void testParsePortNumbers3() throws IOException {
		assertEquals(
			Arrays.asList(new SEManage.Port.PortNumber(10080, 10083)),
			SEManage.Port.parsePortNumbers("10080-10083")
		);
	}

	@Test
	public void testParsePortNumbers4() throws IOException {
		assertEquals(
			Arrays.asList(
				new SEManage.Port.PortNumber(15672, 15672),
				new SEManage.Port.PortNumber(5671, 5672)
			),
			SEManage.Port.parsePortNumbers("15672, 5671-5672")
		);
	}

	@Test
	public void testParsePortNumbers5() throws IOException {
		assertEquals(
			Arrays.asList(
				new SEManage.Port.PortNumber(2427, 2427),
				new SEManage.Port.PortNumber(2727, 2727),
				new SEManage.Port.PortNumber(4569, 4569)
			),
			SEManage.Port.parsePortNumbers("2427, 2727, 4569")
		);
	}

	@Test
	public void testParsePortNumbers6() throws IOException {
		assertEquals(
			Arrays.asList(
				new SEManage.Port.PortNumber(5149, 5149),
				new SEManage.Port.PortNumber(40040, 40040),
				new SEManage.Port.PortNumber(50006, 50008)
			),
			SEManage.Port.parsePortNumbers("5149, 40040, 50006-50008")
		);
	}

	public void testPortNumberMinFrom() throws IOException {
		new SEManage.Port.PortNumber(1, 10);
	}

	public void testPortNumberMaxFrom() throws IOException {
		new SEManage.Port.PortNumber(65535, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberLowFrom() throws IOException {
		new SEManage.Port.PortNumber(0, 10);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberHighFrom() throws IOException {
		new SEManage.Port.PortNumber(65536, 10);
	}

	public void testPortNumberMinTo() throws IOException {
		new SEManage.Port.PortNumber(1, 1);
	}

	public void testPortNumberMaxTo() throws IOException {
		new SEManage.Port.PortNumber(10, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberLowTo() throws IOException {
		new SEManage.Port.PortNumber(10, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberHighTo() throws IOException {
		new SEManage.Port.PortNumber(10, 65536);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberFromBiggerTo() throws IOException {
		new SEManage.Port.PortNumber(10, 1);
	}
}
