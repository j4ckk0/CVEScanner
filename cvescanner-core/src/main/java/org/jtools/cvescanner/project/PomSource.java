package org.jtools.cvescanner.project;

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

import java.util.Optional;

/** Where the poms of a project's dependencies are read from: the local Maven repository, or Gradle's cache. */
interface PomSource {

    /** The pom of group:artifact:version; empty when this source does not hold it, or it cannot be read. */
    Optional<MavenReader.Pom> pom(String group, String artifact, String version);

    /** The folder, as a report says it: forward slashes. */
    String shown();
}
