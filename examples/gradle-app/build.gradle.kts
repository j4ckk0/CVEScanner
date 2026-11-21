// Versions with known vulnerabilities, given three ways: in the version catalog (gradle/libs.versions.toml), in a
// variable, and written out.
plugins {
    java
}

val xstreamVersion = "1.4.17"

dependencies {
    implementation(libs.guava)
    implementation(libs.netty.codec.http)
    implementation(libs.protobuf.java)
    implementation("com.thoughtworks.xstream:xstream:$xstreamVersion")
    implementation("commons-io:commons-io:2.6")
    implementation("org.apache.httpcomponents:httpclient:4.5.12")
    testImplementation("junit:junit:4.12")
}
