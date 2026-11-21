package org.jtools.cvescanner.ignore;

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

import java.util.Locale;
import java.util.Set;
import org.jtools.cvescanner.model.Finding;

/**
 * What a VEX document states of a vulnerability in a package version: its analysis state (CycloneDX's not_affected,
 * false_positive, in_triage, exploitable, resolved…), the justification and the detail it gives. An empty package or
 * version is any, as in the ignore file.
 *
 * @param source the document, as reports name it
 */
public record VexStatement(String id, String pkg, String version, String state, String justification, String detail,
                           String source) {

    /** The states that say the vulnerability does not apply: those set the finding aside. */
    static final Set<String> NOT_APPLYING = Set.of("not_affected", "false_positive");

    public VexStatement {
        state = state == null ? "" : state.strip().toLowerCase(Locale.ROOT);
        justification = justification == null ? "" : justification.strip();
        detail = detail == null ? "" : detail.strip();
    }

    /**
     * Whether it sets its findings aside: not_affected, false_positive. A resolved one does not: the scan still finds
     * the version said to be fixed. in_triage and exploitable change nothing, and are shown with the finding.
     */
    public boolean setsAside() {
        return NOT_APPLYING.contains(state);
    }

    /** The statement as an entry setting its findings aside: its state, justification and detail as its reason. */
    public IgnoreRule asRule() {
        return new IgnoreRule(id, pkg, version, null, said(), 0, source);
    }

    /** "not_affected (code_not_reachable): the JNDI lookup is disabled". */
    public String said() {
        String s = state + (justification.isEmpty() ? "" : " (" + justification + ")");
        return detail.isEmpty() ? s : s + ": " + detail;
    }

    public boolean matches(Finding f) {
        return new IgnoreRule(id, pkg, version, null, "", 0, source).matches(f);
    }
}
