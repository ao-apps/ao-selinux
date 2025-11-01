/*
 * ao-selinux - Java API for managing Security-Enhanced Linux (SELinux).
 * Copyright (C) 2017, 2019, 2020, 2021, 2022  AO Industries, Inc.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import com.aoapps.collections.AoCollections;
import com.aoapps.lang.io.IoUtils;
import com.aoapps.lang.validation.ValidationException;
import com.aoapps.net.IPortRange;
import com.aoapps.net.Port;
import com.aoapps.net.PortRange;
import com.aoapps.net.Protocol;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests {@link SEManagePort}.
 *
 * @author  AO Industries, Inc.
 */
public class SEManagePortTest {

  private static String loadResource(String resource) throws IOException {
    InputStream resourceIn = SEManagePortTest.class.getResourceAsStream(resource);
    if (resourceIn == null) {
      throw new IOException("Resource not found: " + resource);
    }
    try (Reader in = new InputStreamReader(resourceIn, StandardCharsets.UTF_8)) {
      return IoUtils.readFully(in);
    }
  }

  private static String testDataSimpleSubset;
  private static String testDataLocalWithModified8008;
  private static String testDataFullWithModified8008;

  /**
   * Sets up class.
   */
  @BeforeClass
  public static void setUpClass() throws IOException {
    testDataSimpleSubset = loadResource("semanage-port-noheading-list-simple-subset.txt");
    testDataLocalWithModified8008 = loadResource("semanage-port-noheading-list-local-with-modified-8008.txt");
    testDataFullWithModified8008 = loadResource("semanage-port-noheading-list-full-with-modified-8008.txt");
  }

  /**
   * Tears down class.
   */
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
        new TreeSet<>(
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
    SortedMap<IPortRange, String> expected = new TreeMap<>();
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
    SortedMap<IPortRange, String> expected = new TreeMap<>();
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
    for (Protocol protocol : new Protocol[]{Protocol.TCP, Protocol.UDP}) {
      IPortRange lastPortRange = null;
      for (IPortRange portRange : policy.keySet()) {
        if (portRange.getProtocol() == protocol) {
          if (lastPortRange == null) {
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
    for (Protocol protocol : new Protocol[]{Protocol.TCP, Protocol.UDP}) {
      IPortRange lastPortRange = null;
      String lastType = null;
      for (Map.Entry<IPortRange, String> entry : policy.entrySet()) {
        IPortRange portRange = entry.getKey();
        if (portRange.getProtocol() == protocol) {
          String type = entry.getValue();
          if (lastPortRange != null) {
            assertNotEquals(
                "Adjacent ports must be of different types when properly coalesced (" + lastPortRange + ", " + portRange + ")",
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
}
