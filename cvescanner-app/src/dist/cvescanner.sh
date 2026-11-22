#!/bin/sh
# Run CVEScanner with its runtime: the window, or with --no-gui the command line. Arguments are passed to the program,
# after the folder of the database zips (database/, loaded at the start) and of the reports (reports/), both beside the
# program, so that a -o of yours still wins.
dir=$(dirname "$(readlink -f "$0")")
# --man: the manual beside the program (--help, the options, is the program's own)
if [ "${1-}" = "--man" ]; then exec man "$dir/cvescanner.1"; fi
# -XX:-UsePerfData: the JVM's performance counters stay in memory, not in a file of /tmp;
# -XX:+UseCompactObjectHeaders: smaller objects, less memory for a large database.
# cvescanner.aot, Java's AOT cache of the program (pom.xml makes it), for a faster start; read only, and
# silently passed over should it not match the runtime.
aot="$dir/cvescanner.aot"
if [ -f "$aot" ]; then
  exec "$dir/jre/bin/java" -XX:-UsePerfData -XX:+UseCompactObjectHeaders \
    -XX:AOTCache="$aot" -Xlog:aot=off -Xlog:cds=off -jar "$dir/cvescanner.jar" \
    --db-dir "$dir/database" -o "$dir/reports" "$@"
fi
exec "$dir/jre/bin/java" -XX:-UsePerfData -XX:+UseCompactObjectHeaders -jar "$dir/cvescanner.jar" \
  --db-dir "$dir/database" -o "$dir/reports" "$@"
