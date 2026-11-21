/*-
 * #%L
 * CVEScanner core
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
 * CVEScanner's scan, with no window: the projects' dependencies (project), the vulnerability databases read from
 * their zips (db), the matching and the scan as a whole (engine), the CVSS scores for an environment (cvss), what a
 * scan finds (model), the reports (report) and the command line (cli). It needs nothing but the JDK.
 */
module org.jtools.cvescanner.core {
    requires java.xml;
    requires java.net.http;

    exports org.jtools.cvescanner.cli;
    exports org.jtools.cvescanner.cvss;
    exports org.jtools.cvescanner.db;
    exports org.jtools.cvescanner.engine;
    exports org.jtools.cvescanner.json;
    exports org.jtools.cvescanner.model;
    exports org.jtools.cvescanner.project;
    exports org.jtools.cvescanner.report;
    exports org.jtools.cvescanner.version;
}
