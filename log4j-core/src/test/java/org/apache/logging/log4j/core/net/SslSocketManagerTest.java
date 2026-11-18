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
package org.apache.logging.log4j.core.net;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.core.net.ssl.SslConfiguration;
import org.apache.logging.log4j.core.net.ssl.TestConstants;
import org.apache.logging.log4j.core.net.ssl.TrustStoreConfiguration;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Host name verification of {@link SslSocketManager} against a loopback TLS server whose certificate
 * ({@code CN=client.log4j2}, signed by the test CA) names neither {@code localhost} nor {@code 127.0.0.1}.
 */
public class SslSocketManagerTest {

    // Not TestConstants' stores: their certificates expired in 2022 and 2023, which would fail every handshake
    private static final String STORES = "src/test/resources/org/apache/logging/log4j/core/net/SslSocketManagerTest/";

    private static final Layout<?> LAYOUT = PatternLayout.createDefaultLayout();

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "127.0.0.1"})
    public void connection_fails_on_host_name_mismatch_when_verification_is_enabled(final String hostName)
            throws Exception {
        try (final LoopbackTlsServer server = new LoopbackTlsServer();
                final SslSocketManager manager = createSocketManager(hostName, server.getPort(), true)) {
            assertNull(manager.getSocket());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "127.0.0.1"})
    public void connection_succeeds_on_host_name_mismatch_when_verification_is_disabled(final String hostName)
            throws Exception {
        try (final LoopbackTlsServer server = new LoopbackTlsServer();
                final SslSocketManager manager = createSocketManager(hostName, server.getPort(), false)) {
            final Socket socket = manager.getSocket();
            assertNotNull(socket);
            assertTrue(socket.isConnected());
        }
    }

    private static SslSocketManager createSocketManager(
            final String hostName, final int port, final boolean verifyHostName) throws Exception {
        final TrustStoreConfiguration trustStoreConfig = new TrustStoreConfiguration(
                STORES + "truststore.jks", TestConstants::TRUSTSTORE_PWD, TestConstants.TRUSTSTORE_TYPE, null);
        final SslConfiguration sslConfig =
                SslConfiguration.createSSLConfiguration(null, null, trustStoreConfig, verifyHostName);
        return SslSocketManager.getSocketManager(sslConfig, hostName, port, 0, 0, true, LAYOUT, 8192, null);
    }

    private static final class LoopbackTlsServer implements AutoCloseable {

        private final SSLServerSocket serverSocket;

        private LoopbackTlsServer() throws Exception {
            final KeyStore keyStore = KeyStore.getInstance(TestConstants.KEYSTORE_TYPE);
            try (final InputStream in = Files.newInputStream(Paths.get(STORES + "client.log4j2-keystore.jks"))) {
                keyStore.load(in, TestConstants.KEYSTORE_PWD());
            }
            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, TestConstants.KEYSTORE_PWD());
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            serverSocket = (SSLServerSocket)
                    sslContext.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
            final Thread thread = new Thread(this::acceptClients, "SslSocketManagerTest-server");
            thread.setDaemon(true);
            thread.start();
        }

        private int getPort() {
            return serverSocket.getLocalPort();
        }

        private void acceptClients() {
            while (!serverSocket.isClosed()) {
                try (final SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.startHandshake();
                    while (socket.getInputStream().read() >= 0) {
                        // Discard
                    }
                } catch (final Exception ignored) {
                    // The client may abort the handshake or close the connection
                }
            }
        }

        @Override
        public void close() throws Exception {
            serverSocket.close();
        }
    }
}
