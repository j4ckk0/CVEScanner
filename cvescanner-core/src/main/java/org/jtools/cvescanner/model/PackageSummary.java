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


/**
 * A vulnerable package version and its findings together: {@code fixedIn} is the lowest version that fixes every one
 * of them that has a fix, empty when none has; {@code someUnfixed} when some have none.
 */
public record PackageSummary(Severity worst, String ecosystem, String pkg, String version, boolean approximate,
                      String fixedIn, boolean someUnfixed, int vulnerabilities, String advisories, String files) {
    public String displayVersion() { return approximate ? version + " ≈" : version; }

    /** The version to upgrade to, said: "2.15.0", "2.15.0 (some unfixed)", "no fix". */
    public String upgradeTo(I18nLanguage language) {
        if (fixedIn.isEmpty()) return I18n.text(language, "upgrade.noFix");
        return someUnfixed ? I18n.text(language, "upgrade.someUnfixed", fixedIn) : fixedIn;
    }

    public String upgradeTo() { return upgradeTo(I18n.language()); }
}
