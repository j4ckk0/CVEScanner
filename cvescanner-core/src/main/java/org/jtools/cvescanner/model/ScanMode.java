package org.jtools.cvescanner.model;

/*-
 * #%L
 * CVEScanner
 * %%
 * Copyright (C) 2026 jtools.org
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

/**
 * What a scan reads. SOURCES: the projects' manifests (poms, Gradle files, package.json, Python's requirements,
 * pyproject.toml and Pipfile, and their lockfiles, C/C++ manifests). INSTALLED: an installed product, from what it
 * ships (jars, WARs and EARs and the jars inside them, an installed node_modules, a Python site-packages, native
 * libraries), every folder included. Both read the SBOMs, component inventories, pkg-config files and binaries of
 * components off-the-shelf.
 */
public enum ScanMode { SOURCES, INSTALLED }
