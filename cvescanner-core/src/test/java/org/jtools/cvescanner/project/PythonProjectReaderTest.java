package org.jtools.cvescanner.project;

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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Dependency;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PythonProjectReaderTest {

    @TempDir
    Path dir;
    private final List<Phrase> warnings = new ArrayList<>();

    private DependencyCollector scan(String... pathAndText) throws IOException {
        var files = new ArrayList<Path>();
        for (int i = 0; i < pathAndText.length; i += 2) {
            Path p = dir.resolve(pathAndText[i]);
            Files.createDirectories(p.getParent());
            Files.writeString(p, pathAndText[i + 1]);
            files.add(p);
        }
        var col = new DependencyCollector(dir);
        PythonProjectReader.scan(files.stream().filter(p -> !p.getFileName().toString().equals("other.txt")).toList(), col, warnings::add);
        return col;
    }

    private static TreeSet<String> rows(DependencyCollector col) {
        var out = new TreeSet<String>();
        for (Dependency d : col.deps) out.add(d.file() + " " + d.name() + " " + d.version() + (d.approximate() ? "≈" : "") + " " + d.scope());
        for (var u : col.unresolved) out.add(u.file() + " " + u.name() + " ! " + u.reason().key());
        return out;
    }

    @Test
    void specifiersGiveAnExactVersionTheLowestOrWhyNone() {
        assertEquals(new PythonProjectReader.Version("1.2.3", true, null), PythonProjectReader.pep440Version("==1.2.3"));
        assertEquals(new PythonProjectReader.Version("1.2", false, null), PythonProjectReader.pep440Version(">=1.2,<2"));
        assertEquals(new PythonProjectReader.Version("1.4.2", false, null), PythonProjectReader.pep440Version("~=1.4.2"));
        assertEquals(new PythonProjectReader.Version("1.2", false, null), PythonProjectReader.pep440Version("==1.2.*"));
        assertEquals("reason.noLowerBound", PythonProjectReader.pep440Version("<2").reason().key());
        assertEquals("reason.unpinned", PythonProjectReader.pep440Version("").reason().key());
        assertEquals(new PythonProjectReader.Version("2.25", false, null), PythonProjectReader.poetryVersion("^2.25"));
        assertEquals(new PythonProjectReader.Version("1.2.3", true, null), PythonProjectReader.poetryVersion("1.2.3"));
        assertEquals("reason.unpinned", PythonProjectReader.poetryVersion("*").reason().key());
    }

    @Test
    void requirementsFollowTheirIncludesAndLeaveWhatIsNotARegistrysPackage() throws IOException {
        var col = scan("app/requirements.txt", """
                -r other.txt
                -r requirements.txt
                Django[bcrypt] >= 3.1 ; python_version >= "3.8"   # the web framework
                PyYAML==5.3.1 \\
                    --hash=sha256:abc
                git+https://example.org/tool.git#egg=tool
                https://example.org/wheel.whl
                mypkg @ https://example.org/mypkg.whl
                -e ./local#egg=local
                --index-url https://pypi.org/simple
                """, "app/other.txt", "requests==2.25.0\n");
        assertEquals(new TreeSet<>(List.of(
                "app/other.txt requests 2.25.0 requirements",
                "app/requirements.txt Django 3.1≈ requirements",
                "app/requirements.txt PyYAML 5.3.1 requirements",
                "app/requirements.txt local ! reason.nonRegistry",
                "app/requirements.txt mypkg ! reason.nonRegistry",
                "app/requirements.txt tool ! reason.nonRegistry")), rows(col));
    }

    @Test
    void aLockfilesVersionsWinTheDeclaredOnesDirect() throws IOException {
        var col = scan("p/pyproject.toml", """
                [project]
                dependencies = ["requests>=2.25"]
                [dependency-groups]
                dev = ["pytest"]
                """, "p/requirements.txt", "requests==2.0\n", "p/uv.lock", """
                version = 1
                [[package]]
                name = "requests"
                version = "2.25.1"
                source = { registry = "https://pypi.org/simple" }
                [[package]]
                name = "urllib3"
                version = "1.26.4"
                source = { registry = "https://pypi.org/simple" }
                [[package]]
                name = "pytest"
                version = "7.4.0"
                source = { registry = "https://pypi.org/simple" }
                [[package]]
                name = "tool"
                version = "0.1"
                source = { git = "https://example.org/tool.git" }
                [[package]]
                name = "p"
                version = "0.1"
                source = { editable = "." }
                """);
        assertEquals(new TreeSet<>(List.of("p/uv.lock pytest 7.4.0 direct (dev)", "p/uv.lock requests 2.25.1 direct",
                "p/uv.lock tool ! reason.nonRegistry", "p/uv.lock urllib3 1.26.4 transitive")), rows(col),
                "the lockfile's, the requirements of the folder not read again");
    }

    @Test
    void poetryAndPipenv() throws IOException {
        var col = scan("po/pyproject.toml", """
                [tool.poetry.dependencies]
                python = "^3.9"
                Requests = "^2.25"
                [tool.poetry.group.dev.dependencies]
                pytest = "^7"
                """, "po/poetry.lock", """
                [[package]]
                name = "requests"
                version = "2.25.0"
                [[package]]
                name = "pytest"
                version = "7.0.0"
                [[package]]
                name = "idna"
                version = "2.10"
                category = "main"
                """, "pe/Pipfile", "[packages]\ndjango = \"*\"\n[dev-packages]\nblack = \"*\"\n", "pe/Pipfile.lock", """
                {"_meta": {}, "default": {"django": {"version": "==3.1.0"}, "pytz": {"version": "==2021.1"}},
                 "develop": {"black": {"version": "==22.1.0"}, "mine": {"editable": true, "path": "."}}}
                """);
        assertEquals(new TreeSet<>(List.of("pe/Pipfile.lock black 22.1.0 direct (dev)", "pe/Pipfile.lock django 3.1.0 direct",
                "pe/Pipfile.lock mine ! reason.nonRegistry", "pe/Pipfile.lock pytz 2021.1 transitive",
                "po/poetry.lock idna 2.10 transitive", "po/poetry.lock pytest 7.0.0 direct (dev)", "po/poetry.lock requests 2.25.0 direct")),
                rows(col));
    }

    @Test
    void aPyprojectsRangeGivesWayToARequirementsPin() throws IOException {
        var col = scan("q/pyproject.toml", "[project]\ndependencies = [\"Jinja2>=2.10,<3\", \"flask~=2.0.1\"]\n",
                "q/requirements.txt", "jinja2==2.11.2\n");
        assertEquals(new TreeSet<>(List.of("q/pyproject.toml flask 2.0.1≈ dependencies", "q/requirements.txt jinja2 2.11.2 requirements")),
                rows(col));
    }

    @Test
    void anUnreadablePyprojectLeavesTheFoldersOtherFilesRead() throws IOException {
        var col = scan("u/pyproject.toml", "[tool.odd\nx = 1\n", "u/requirements.txt", "requests==2.25.0\n",
                "v/pyproject.toml", "[project]\ndependencies = [\"requests\"]\n", "v/poetry.lock", "[[package]\nname = 1\n");
        assertEquals(new TreeSet<>(List.of("u/requirements.txt requests 2.25.0 requirements", "v/pyproject.toml requests ! reason.unpinned")),
                rows(col), "an unreadable lockfile: the folder's manifests read instead");
        assertEquals(2, warnings.size(), warnings.toString());
    }

    @Test
    void anUnreadableFileIsSaidAndTheOthersRead() throws IOException {
        var col = scan("bad/pyproject.toml", "[project\n", "good/requirements.txt", "requests==2.25.0\n");
        assertEquals(new TreeSet<>(List.of("good/requirements.txt requests 2.25.0 requirements")), rows(col));
        assertEquals(List.of("warning.skipped"), warnings.stream().map(Phrase::key).toList());
    }
}
