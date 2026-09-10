/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache license, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 */
package org.apache.logging.log4j.core.layout;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.apache.logging.log4j.core.impl.ContextDataFactory;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.SimpleMessage;
import org.apache.logging.log4j.spi.DefaultThreadContextStack;
import org.apache.logging.log4j.util.StringMap;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * CVE-2026-34480: XmlLayout emitted characters XML 1.0 forbids.
 *
 * <p>Ported from upstream's {@code XmlLayoutJUnit5Test}, with the code points passed as ints and
 * the strings built here, because upstream's {@code @ValueSource(strings = ...)} carries raw
 * control bytes in the source file and a {@code .patch} is byte-sensitive. The cases, and what is
 * asserted about each, are upstream's.
 *
 * <p>Both directions matter. Sanitizing everything would pass the first test and fail the second,
 * so the pair is what shows the fix replaces exactly the forbidden code points.
 */
class XmlLayoutSanitizationTest {

    private static final String REPLACEMENT = "\uFFFD";

    private static Log4jLogEvent createLogEventWithString(final String str) {
        final Marker marker = MarkerManager.getMarker("marker" + str);

        final RuntimeException thrown = new RuntimeException("thrown" + str);
        thrown.addSuppressed(new IllegalStateException("suppressed" + str));

        final StringMap contextData = ContextDataFactory.createContextData();
        contextData.putValue("mdcKey" + str, "mdcValue" + str);

        // 2.17.2's constructor takes useStack; upstream's no-arg one arrived later.
        final DefaultThreadContextStack contextStack = new DefaultThreadContextStack(true);
        contextStack.clear();
        contextStack.push("contextStack" + str);

        final StackTraceElement source =
                new StackTraceElement("class" + str, "method" + str, "file" + str + ".java", 123);

        return Log4jLogEvent.newBuilder()
                .setLoggerName("logger" + str)
                .setMarker(marker)
                .setLoggerFqcn("fqcn" + str)
                .setLevel(Level.DEBUG)
                .setMessage(new SimpleMessage("message" + str))
                .setThrown(thrown)
                .setContextData(contextData)
                .setContextStack(contextStack)
                .setThreadName("thread" + str)
                .setSource(source)
                .setTimeMillis(1L)
                .build();
    }

    private static String serialize(final String str) {
        final AbstractJacksonLayout layout = XmlLayout.newBuilder()
                .setCompact(true)
                .setIncludeStacktrace(true)
                .setLocationInfo(true)
                .setProperties(true)
                .build();
        return layout.toSerializable(createLogEventWithString(str));
    }

    @ParameterizedTest
    @ValueSource(
            ints = {
                0x0000,
                0x001F,
                // hi surrogate
                0xD800,
                // low surrogate
                0xDC00,
                // invalid chars
                0xFFFE,
                0xFFFF
            })
    void invalidXmlCharsAreSanitized(final int codePoint) {
        final String invalidXmlChars = String.valueOf((char) codePoint);

        final String str = serialize(invalidXmlChars);

        // On the unfixed baseline this is where it fails, and not by emitting the character:
        // Woodstox throws inside the layout, log4j routes that to its own status logger, and
        // toSerializable hands back an empty string, and the whole event is lost.
        assertFalse(str.contains(invalidXmlChars), "forbidden code point reached the output");
        assertTrue(str.contains(REPLACEMENT), "expected U+FFFD in place of the forbidden code point");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                " ",
                "A",
                // First character from supplementary plane
                "\uD801\uDC00",
                // Last character from supplementary plane
                "\uDBFF\uDFFF"
            })
    void validXmlCharsAreKept(final String validXmlChars) {
        final String str = serialize(validXmlChars);

        assertTrue(str.contains(validXmlChars), "a valid code point was altered");
        assertFalse(str.contains(REPLACEMENT), "a valid code point was replaced with U+FFFD");
    }
}
