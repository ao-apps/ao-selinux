/*
 * ao-selinux - Java API for managing Security-Enhanced Linux (SELinux).
 * Copyright (C) 2017, 2021, 2022  AO Industries, Inc.
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

import com.aoapps.lang.ProcessResult;
import java.io.IOException;

/**
 * Wraps functions of the <code>semanage</code> commands.
 *
 * @author  AO Industries, Inc.
 */
final class SEManage {

  /** Make no instances. */
  private SEManage() {
    throw new AssertionError();
  }

  // Unused: private static final Logger logger = Logger.getLogger(SEManage.class.getName());

  /**
   * The full path to the <code>semanage</code> executable.
   */
  private static final String SEMANAGE_EXE = "/usr/sbin/semanage";

  /**
   * Serializes access to the underlying <code>semanage</code> command.
   */
  private static class SemanageLock {
    private SemanageLock() {
      // Empty lock class to help heap profile
    }
  }
  static final SemanageLock semanageLock = new SemanageLock();

  /**
   * Calls the <code>semanage</code> command with the given arguments
   *
   * @throws  IOException  when I/O exception or non-zero exit value
   */
  static ProcessResult execSemanage(String ... args) throws IOException {
    String[] command = new String[1 + args.length];
    command[0] = SEMANAGE_EXE;
    System.arraycopy(args, 0, command, 1, args.length);
    ProcessResult result;
    synchronized (semanageLock) {
      result = ProcessResult.exec(command);
    }
    if (result.getExitVal() != 0) {
      throw new IOException(result.getStderr());
    }
    return result;
  }
}
