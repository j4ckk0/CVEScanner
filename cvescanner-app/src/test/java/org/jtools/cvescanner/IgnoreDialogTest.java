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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.junit.jupiter.api.Test;

/** The last day an entry applies, as the Ignore dialog reads it: empty for ever, a date to come, nothing else. */
class IgnoreDialogTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 11, 21);

    @Test
    void emptyIsForEverAndADateToComeOrTodayIsKept() {
        assertNull(IgnoreDialog.until("  ", TODAY));
        assertEquals(TODAY, IgnoreDialog.until("2026-11-21", TODAY));
        assertEquals(LocalDate.of(2027, 6, 30), IgnoreDialog.until(" 2027-06-30 ", TODAY));
    }

    @Test
    void anythingElseIsRefusedSayingWhy() {
        I18n.use(I18nLanguage.ENGLISH);
        var notADate = assertThrows(IllegalArgumentException.class, () -> IgnoreDialog.until("30/06/2027", TODAY));
        assertTrue(notADate.getMessage().contains("30/06/2027"), notADate.getMessage());
        var past = assertThrows(IllegalArgumentException.class, () -> IgnoreDialog.until("2026-11-20", TODAY));
        assertTrue(past.getMessage().contains("past"), past.getMessage());
    }
}
