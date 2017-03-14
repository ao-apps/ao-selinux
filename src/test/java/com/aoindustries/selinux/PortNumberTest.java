package com.aoindustries.selinux;

import java.io.IOException;
import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class PortNumberTest {
	
	public PortNumberTest() {
	}

	@Test
	public void testParsePortNumbers1() throws IOException {
		assertEquals(
			Arrays.asList(new PortNumber(7001)),
			PortNumber.parsePortNumbers("7001")
		);
	}

	@Test
	public void testParsePortNumbers2() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortNumber(7000),
				new PortNumber(7005)
			),
			PortNumber.parsePortNumbers("7000, 7005")
		);
	}

	@Test
	public void testParsePortNumbers3() throws IOException {
		assertEquals(
			Arrays.asList(new PortNumber(10080, 10083)),
			PortNumber.parsePortNumbers("10080-10083")
		);
	}

	@Test
	public void testParsePortNumbers4() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortNumber(15672),
				new PortNumber(5671, 5672)
			),
			PortNumber.parsePortNumbers("15672, 5671-5672")
		);
	}

	@Test
	public void testParsePortNumbers5() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortNumber(2427),
				new PortNumber(2727),
				new PortNumber(4569)
			),
			PortNumber.parsePortNumbers("2427, 2727, 4569")
		);
	}

	@Test
	public void testParsePortNumbers6() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortNumber(5149),
				new PortNumber(40040),
				new PortNumber(50006, 50008)
			),
			PortNumber.parsePortNumbers("5149, 40040, 50006-50008")
		);
	}

	public void testPortNumberMinFrom() throws IOException {
		new PortNumber(1, 10);
	}

	public void testPortNumberMaxFrom() throws IOException {
		new PortNumber(65535, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberLowFrom() throws IOException {
		new PortNumber(0, 10);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberHighFrom() throws IOException {
		new PortNumber(65536, 10);
	}

	public void testPortNumberMinTo() throws IOException {
		new PortNumber(1, 1);
	}

	public void testPortNumberMaxTo() throws IOException {
		new PortNumber(10, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberLowTo() throws IOException {
		new PortNumber(10, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberHighTo() throws IOException {
		new PortNumber(10, 65536);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortNumberFromBiggerTo() throws IOException {
		new PortNumber(10, 1);
	}

	@Test
	public void testOverlaps1() {
		assertTrue(
			new PortNumber(10).overlaps(
				new PortNumber(10)
			)
		);
	}

	@Test
	public void testOverlaps2() {
		assertTrue(
			new PortNumber(5, 10).overlaps(
				new PortNumber(10)
			)
		);
	}

	@Test
	public void testOverlaps3() {
		assertTrue(
			new PortNumber(5, 10).overlaps(
				new PortNumber(5)
			)
		);
	}

	@Test
	public void testOverlaps4() {
		assertFalse(
			new PortNumber(5).overlaps(
				new PortNumber(11)
			)
		);
	}

	@Test
	public void testOverlaps5() {
		assertFalse(
			new PortNumber(5, 10).overlaps(
				new PortNumber(11)
			)
		);
	}

	@Test
	public void testOverlaps6() {
		assertFalse(
			new PortNumber(5, 10).overlaps(
				new PortNumber(4)
			)
		);
	}

	@Test
	public void testOverlaps7() {
		assertTrue(
			new PortNumber(5, 10).overlaps(
				new PortNumber(1, 5)
			)
		);
	}

	@Test
	public void testOverlaps8() {
		assertTrue(
			new PortNumber(5, 10).overlaps(
				new PortNumber(10, 15)
			)
		);
	}

	@Test
	public void testOverlaps9() {
		assertFalse(
			new PortNumber(5, 10).overlaps(
				new PortNumber(1, 4)
			)
		);
	}

	@Test
	public void testOverlaps10() {
		assertFalse(
			new PortNumber(5, 10).overlaps(
				new PortNumber(11, 15)
			)
		);
	}
}
