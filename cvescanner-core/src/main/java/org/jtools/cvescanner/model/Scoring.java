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


import java.util.List;
import org.jtools.cvescanner.cvss.Cvss;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Score;
import org.jtools.cvescanner.cvss.Severity;

/** Applies the chosen CVSS version and environment to a finding. */
public final class Scoring {
    private Scoring() {}

    public static Finding apply(Finding f, Environment env, boolean preferV4) {
        Rating r = f.rating();
        String vector = preferV4 ? (r.cvss4() != null ? r.cvss4() : r.cvss3()) : (r.cvss3() != null ? r.cvss3() : r.cvss4());
        Double base = vector == null ? null : Cvss.baseScore(vector);
        if (base == null) vector = null;
        Severity baseSeverity;
        if (base != null) baseSeverity = Severity.fromScore(base);
        else if (r.score() != null) { base = r.score(); baseSeverity = Severity.fromScore(base); }
        else baseSeverity = r.severity();
        String envVector = null;
        Double envScore = null;
        if (vector != null && env.active()) {
            envVector = Cvss.applyEnvironment(vector, env);
            envScore = Cvss.environmentalScore(envVector);
            if (envScore == null) envVector = null;
        }
        Severity effective = envScore != null ? Severity.fromScore(envScore) : baseSeverity;
        return f.rescored(effective, new Score(vector == null ? null : Cvss.version(vector), vector, base, baseSeverity, envVector, envScore));
    }

    public static List<Finding> applyAll(List<Finding> findings, Environment env, boolean preferV4) {
        return findings.stream().map(f -> apply(f, env, preferV4)).sorted(Finding.ORDER).toList();
    }
}
