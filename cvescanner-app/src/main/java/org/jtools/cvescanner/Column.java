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


import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * A column of a table: known by its key, titled in the language in use; its values read from a row. An editable one
 * (a checkbox) also says which rows it may be changed on, and what a change does.
 */
record Column<T>(String key, Class<?> type, int width, Function<T, ?> value, Predicate<T> editable, BiConsumer<T, Object> setter) {

    Column(String key, Class<?> type, int width, Function<T, ?> value) {
        this(key, type, width, value, _ -> false, null);
    }
}
