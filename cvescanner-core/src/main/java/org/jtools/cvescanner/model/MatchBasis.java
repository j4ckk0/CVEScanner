package org.jtools.cvescanner.model;

import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;

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


/** How a finding was matched to the dependency. */
public enum MatchBasis {
    /**
     * An advisory naming the package; a CVE record naming it, or only its name; NVD naming a component's vendor and
     * product (CPE), or only its product, its vendor unknown (CPE_PRODUCT, to check); an advisory naming an artifact a
     * jar without coordinates bears the name of, whatever its group (ADVISORY_NAME, to check).
     */
    ADVISORY, CVE_PACKAGE, CVE_NAME, CPE, CPE_PRODUCT, ADVISORY_NAME;

    /** Matched by a name only: to check that it is the package (--hide-name-matches leaves these out). */
    public boolean byName() {
        return this == CVE_NAME || this == ADVISORY_NAME;
    }

    /** How it is shown in the language in use: "Advisory", "CVE name match ⚠". */
    public String label() { return label(I18n.language()); }

    public String label(I18nLanguage language) { return I18n.text(language, "match." + name()); }
}
