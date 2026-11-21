package org.jtools.cvescanner;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import org.junit.jupiter.api.Test;

/** A column with a setter can be changed, on the rows it allows only; one without cannot be changed at all. */
class ListTableModelTest {

    @Test
    void aTickIsSetOnlyWhereItCanBe() {
        var ticked = new HashSet<String>();
        var model = new ListTableModel<String>(List.of(
                new Column<String>("column.apply", Boolean.class, 70, s -> ticked.contains(s), s -> !s.equals("cots"),
                        (s, v) -> { if (Boolean.TRUE.equals(v)) ticked.add(s); else ticked.remove(s); }),
                new Column<String>("column.package", String.class, 100, s -> s)));
        model.setRows(List.of("lodash", "cots"));
        assertTrue(model.isCellEditable(0, 0));
        assertFalse(model.isCellEditable(1, 0), "a row the column does not allow");
        assertFalse(model.isCellEditable(0, 1), "a column without a setter");
        model.setValueAt(true, 0, 0);
        model.setValueAt(true, 1, 0);
        assertEquals(java.util.Set.of("lodash"), ticked);
        model.setValueAt(false, 0, 0);
        assertTrue(ticked.isEmpty());
    }
}
