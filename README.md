# [<img src="ao-logo.png" alt="AO Logo" width="35" height="40">](https://github.com/ao-apps) [AO SELinux](https://github.com/ao-apps/ao-selinux)

[![project: current stable](https://aoindustries.com/ao-badges/project-current-stable.svg)](https://aoindustries.com/life-cycle#project-current-stable)
[![management: production](https://aoindustries.com/ao-badges/management-production.svg)](https://aoindustries.com/life-cycle#management-production)
[![packaging: active](https://aoindustries.com/ao-badges/packaging-active.svg)](https://aoindustries.com/life-cycle#packaging-active)  
[![java: &gt;= 8](https://aoindustries.com/ao-badges/java-8.svg)](https://docs.oracle.com/javase/8/)
[![semantic versioning: 2.0.0](https://aoindustries.com/ao-badges/semver-2.0.0.svg)](http://semver.org/spec/v2.0.0.html)
[![license: LGPL v3](https://aoindustries.com/ao-badges/license-lgpl-3.0.svg)](https://www.gnu.org/licenses/lgpl-3.0)

[![Build](https://github.com/ao-apps/ao-selinux/workflows/Build/badge.svg?branch=master)](https://github.com/ao-apps/ao-selinux/actions?query=workflow%3ABuild)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.aoindustries/ao-selinux/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.aoindustries/ao-selinux)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps.platform%3Aaoapps-selinux&metric=alert_status)](https://sonarcloud.io/dashboard?branch=master&id=com.aoapps.platform%3Aaoapps-selinux)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps.platform%3Aaoapps-selinux&metric=ncloc)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps.platform%3Aaoapps-selinux&metric=ncloc)  
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps.platform%3Aaoapps-selinux&metric=reliability_rating)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps.platform%3Aaoapps-selinux&metric=Reliability)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps.platform%3Aaoapps-selinux&metric=security_rating)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps.platform%3Aaoapps-selinux&metric=Security)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps.platform%3Aaoapps-selinux&metric=sqale_rating)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps.platform%3Aaoapps-selinux&metric=Maintainability)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?branch=master&project=com.aoapps.platform%3Aaoapps-selinux&metric=coverage)](https://sonarcloud.io/component_measures?branch=master&id=com.aoapps.platform%3Aaoapps-selinux&metric=Coverage)

Java API for managing Security-Enhanced Linux (SELinux).

## Project Links
* [Project Home](https://aoindustries.com/ao-selinux/)
* [Changelog](https://aoindustries.com/ao-selinux/changelog)
* [API Docs](https://aoindustries.com/ao-selinux/apidocs/)
* [Maven Central Repository](https://central.sonatype.com/artifact/com.aoindustries/ao-selinux)
* [GitHub](https://github.com/ao-apps/ao-selinux)

## Features
* Clean programmatic access to [semanage](https://fedoraproject.org/wiki/SELinux/semanage).
* Implementation of `semanage port` commands:
    * Easily reconfigure all ports for a given SELinux type.
    * Automatically coalesces adjacent port ranges.
    * Presents a single cohesive view of all ports, hiding the nuance and complexity of the interactions between default policy and local policy.
    * Supports seamlessly overriding default policy.
    * Detects conflicts in local policy between different SELinux types.
* Small footprint, minimal dependencies - not part of a big monolithic package.

## Motivation
While migrating our servers to CentOS 7 we are running with SELinux in enforcing mode.  Our server configuration process, [AOServ Daemon](https://github.com/ao-apps/aoserv-daemon), is written in the Java programming language.  We desire a clean interface to SELinux without having to operate with `semanage` and other commands directly.

## Evaluated Alternatives
We were unable to find any existing implementations via [GitHub](https://github.com/search?utf8=%E2%9C%93&q=java+selinux&type=Repositories&ref=searchresults), [The Central Repository](https://central.sonatype.com/search?q=selinux), or [Google Search](https://www.google.com/search?q=java+api+for+selinux).

## Contact Us
For questions or support, please [contact us](https://aoindustries.com/contact):

Email: [support@aoindustries.com](mailto:support@aoindustries.com)  
Phone: [1-800-519-9541](tel:1-800-519-9541)  
Phone: [+1-251-607-9556](tel:+1-251-607-9556)  
Web: https://aoindustries.com/contact
