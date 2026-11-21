package org.jtools.cvescanner.cots;

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

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The vendor:product NVD files the usual components off-the-shelf under (their CPEs), and the names they go by in an
 * inventory, an SBOM, a build manifest or a binary: "GDAL" is osgeo:gdal, "avcodec" ffmpeg:ffmpeg. Each pair is one
 * NVD's feeds use. A name outside the table stays a product alone, matched by product only, to check.
 */
public final class KnownProducts {

    private static final Map<String, String> BY_NAME = new HashMap<>();
    /** Products NVD files one component's CVEs under, each of a group the other's too: curl's under curl and libcurl. */
    private static final List<Set<String>> SAME_COMPONENT = List.of(Set.of("curl", "libcurl"));

    static {
        known("osgeo:gdal", "gdal", "libgdal");
        known("ffmpeg:ffmpeg", "ffmpeg", "libavcodec", "avcodec", "libavformat", "avformat", "libavutil", "avutil",
                "libswscale", "swscale", "libavfilter", "avfilter", "libswresample", "swresample");
        known("openssl:openssl", "openssl", "libssl", "libcrypto");
        known("zlib:zlib", "zlib", "libz", "zlib1");
        known("haxx:curl", "curl");
        known("haxx:libcurl", "libcurl");
        known("sqlite:sqlite", "sqlite", "sqlite3", "libsqlite3");
        known("xmlsoft:libxml2", "libxml2", "xml2");
        known("xmlsoft:libxslt", "libxslt", "xslt");
        known("libpng:libpng", "libpng", "png", "libpng16");
        known("libtiff:libtiff", "libtiff", "tiff");
        known("libjpeg-turbo:libjpeg-turbo", "libjpeg-turbo", "jpeg-turbo", "turbojpeg", "libturbojpeg");
        known("libexpat_project:libexpat", "expat", "libexpat");
        known("freedesktop:poppler", "poppler", "libpoppler");
        known("imagemagick:imagemagick", "imagemagick", "magick");
        known("boost:boost", "boost");
        known("qt:qt", "qt", "qt5", "qt6");
        known("webmproject:libwebp", "libwebp", "webp");
        known("freetype:freetype", "freetype", "libfreetype");
        known("libarchive:libarchive", "libarchive");
        known("uclouvain:openjpeg", "openjpeg", "libopenjp2", "openjp2");
        known("hdfgroup:hdf5", "hdf5", "libhdf5");
        known("unidata:netcdf", "netcdf", "libnetcdf");
        known("pcre:pcre2", "pcre2", "libpcre2");
        known("nghttp2:nghttp2", "nghttp2", "libnghttp2");
        known("libssh2:libssh2", "libssh2");
        known("google:protobuf", "protobuf", "libprotobuf");
        known("gnu:glibc", "glibc");
        known("videolan:vlc", "vlc", "libvlc");
        known("libraw:libraw", "libraw");
        known("jasper_project:jasper", "jasper", "libjasper");
    }

    private KnownProducts() {
    }

    private static void known(String id, String... names) {
        for (String name : names) BY_NAME.put(name, id);
        BY_NAME.put(id.substring(id.indexOf(':') + 1), id);
    }

    /** The component's name for the scan: vendor:product when the name is known, else the name itself in lower case. */
    public static String identify(String name) {
        String key = name.strip().toLowerCase(Locale.ROOT);
        return BY_NAME.getOrDefault(key, key);
    }

    /** The products a component's CVEs are filed under: its own, and those of the same component (curl, libcurl). */
    public static Set<String> products(String product) {
        for (Set<String> group : SAME_COMPONENT) if (group.contains(product)) return group;
        return Set.of(product);
    }

    /** Whether this name is one of a known component's. */
    public static boolean isKnown(String name) {
        return BY_NAME.containsKey(name.strip().toLowerCase(Locale.ROOT));
    }
}
