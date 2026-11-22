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

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/** Edits of one file made in turn, as one: an override under each dependent of a package. */
record EditAll(List<Step.Edit> edits) implements Step.Edit {

    EditAll {
        edits = List.copyOf(edits);
        if (edits.isEmpty()) throw new IllegalArgumentException("no edit");
    }

    @Override
    public Path file() {
        return edits.getFirst().file();
    }

    @Override
    public String apply(String text) {
        String result = text;
        for (Step.Edit e : edits) {
            result = e.apply(result);
            if (result == null) return null;
        }
        return result;
    }

    @Override
    public String shown() {
        var sb = new StringBuilder(edits.getFirst().shown());
        for (Step.Edit e : edits.subList(1, edits.size())) sb.append(", ").append(e.shown().substring(e.file().getFileName().toString().length() + 2));
        return sb.toString();
    }

    @Override
    public Path proof() {
        return edits.stream().map(Step.Edit::proof).filter(Objects::nonNull).findFirst().orElse(null);
    }
}
