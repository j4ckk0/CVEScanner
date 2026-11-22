package org.jtools.cvescanner.fix;

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

import java.util.List;
import org.jtools.cvescanner.i18n.Phrase;

/**
 * How a fix would be applied: its steps, or why it cannot be.
 *
 * @param notApplicable why the fix cannot be applied; null when it can
 * @param requirement   what was checked of the new version (the Java or Node it needs), or why nothing was; null when
 *                      nothing applies
 * @param majorJump     applied only once the user confirms: the major version changes, or a transitive package's new
 *                      version leaves what a dependent asks (or what they ask is not known)
 * @param notes         what else to know: a version shared with other packages, raised for them
 */
public record FixPlan(FixRequest request, List<Step> steps, Phrase notApplicable, Phrase requirement, boolean majorJump,
                      List<Phrase> notes) {

    public FixPlan {
        steps = List.copyOf(steps);
        notes = List.copyOf(notes);
    }

    FixPlan withNote(Phrase note) {
        var all = new java.util.ArrayList<>(notes);
        all.add(note);
        return new FixPlan(request, steps, notApplicable, requirement, majorJump, all);
    }

    /** Whether the major version changes (2.x to 3.x): its API may too. */
    public boolean majorVersionChange() {
        return FixPlanner.majorJump(request);
    }

    public boolean applicable() {
        return notApplicable == null;
    }

    static FixPlan not(FixRequest request, Phrase why) {
        return new FixPlan(request, List.of(), why, null, false, List.of());
    }
}
