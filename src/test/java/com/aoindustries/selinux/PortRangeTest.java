package com.aoindustries.selinux;

import java.io.IOException;
import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class PortRangeTest {
	
	public PortRangeTest() {
	}

	@Test
	public void testParsePortRanges1() throws IOException {
		assertEquals(
			Arrays.asList(new PortRange(7001)),
			PortRange.parsePortRanges("7001")
		);
	}

	@Test
	public void testParsePortRanges2() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortRange(7000),
				new PortRange(7005)
			),
			PortRange.parsePortRanges("7000, 7005")
		);
	}

	@Test
	public void testParsePortRanges3() throws IOException {
		assertEquals(
			Arrays.asList(new PortRange(10080, 10083)),
			PortRange.parsePortRanges("10080-10083")
		);
	}

	@Test
	public void testParsePortRanges4() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortRange(15672),
				new PortRange(5671, 5672)
			),
			PortRange.parsePortRanges("15672, 5671-5672")
		);
	}

	@Test
	public void testParsePortRanges5() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortRange(2427),
				new PortRange(2727),
				new PortRange(4569)
			),
			PortRange.parsePortRanges("2427, 2727, 4569")
		);
	}

	@Test
	public void testParsePortRanges6() throws IOException {
		assertEquals(
			Arrays.asList(
				new PortRange(5149),
				new PortRange(40040),
				new PortRange(50006, 50008)
			),
			PortRange.parsePortRanges("5149, 40040, 50006-50008")
		);
	}

	public void testPortRangeMinFrom() throws IOException {
		new PortRange(1, 10);
	}

	public void testPortRangeMaxFrom() throws IOException {
		new PortRange(65535, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeLowFrom() throws IOException {
		new PortRange(0, 10);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeHighFrom() throws IOException {
		new PortRange(65536, 10);
	}

	public void testPortRangeMinTo() throws IOException {
		new PortRange(1, 1);
	}

	public void testPortRangeMaxTo() throws IOException {
		new PortRange(10, 65535);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeLowTo() throws IOException {
		new PortRange(10, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeHighTo() throws IOException {
		new PortRange(10, 65536);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testPortRangeFromBiggerTo() throws IOException {
		new PortRange(10, 1);
	}

	@Test
	public void testOverlaps1() {
		assertTrue(
			new PortRange(10).overlaps(
				new PortRange(10)
			)
		);
	}

	@Test
	public void testOverlaps2() {
		assertTrue(
			new PortRange(5, 10).overlaps(
				new PortRange(10)
			)
		);
	}

	@Test
	public void testOverlaps3() {
		assertTrue(
			new PortRange(5, 10).overlaps(
				new PortRange(5)
			)
		);
	}

	@Test
	public void testOverlaps4() {
		assertFalse(
			new PortRange(5).overlaps(
				new PortRange(11)
			)
		);
	}

	@Test
	public void testOverlaps5() {
		assertFalse(
			new PortRange(5, 10).overlaps(
				new PortRange(11)
			)
		);
	}

	@Test
	public void testOverlaps6() {
		assertFalse(
			new PortRange(5, 10).overlaps(
				new PortRange(4)
			)
		);
	}

	@Test
	public void testOverlaps7() {
		assertTrue(
			new PortRange(5, 10).overlaps(
				new PortRange(1, 5)
			)
		);
	}

	@Test
	public void testOverlaps8() {
		assertTrue(
			new PortRange(5, 10).overlaps(
				new PortRange(10, 15)
			)
		);
	}

	@Test
	public void testOverlaps9() {
		assertFalse(
			new PortRange(5, 10).overlaps(
				new PortRange(1, 4)
			)
		);
	}

	@Test
	public void testOverlaps10() {
		assertFalse(
			new PortRange(5, 10).overlaps(
				new PortRange(11, 15)
			)
		);
	}
}
