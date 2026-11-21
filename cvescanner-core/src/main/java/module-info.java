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
 * CVEScanner's scan, with no window: the projects' dependencies (project), the vulnerability databases read from
 * their zips (db), the matching and the scan as a whole (engine), the CVSS scores for an environment (cvss), what a
 * scan finds (model), the findings an ignore file sets aside (ignore), the reports (report), the command line (cli)
 * and the languages (i18n). It needs nothing but the JDK.
 */
module org.jtools.cvescanner.core {
    requires java.xml;

    exports org.jtools.cvescanner.cli;
    exports org.jtools.cvescanner.cots;
    exports org.jtools.cvescanner.cvss;
    exports org.jtools.cvescanner.db;
    exports org.jtools.cvescanner.engine;
    exports org.jtools.cvescanner.fix;
    exports org.jtools.cvescanner.i18n;
    exports org.jtools.cvescanner.ignore;
    exports org.jtools.cvescanner.installed;
    exports org.jtools.cvescanner.json;
    exports org.jtools.cvescanner.model;
    exports org.jtools.cvescanner.project;
    exports org.jtools.cvescanner.report;
    exports org.jtools.cvescanner.version;
    // not exported: i18n.texts (this jar's texts)

    // the texts of every jar, its own among them (I18n)
    uses org.jtools.cvescanner.i18n.I18nTexts;
    provides org.jtools.cvescanner.i18n.I18nTexts with org.jtools.cvescanner.i18n.texts.CoreTexts;
}
