/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.RSAKey
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.ParseJarmOptionNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByValue
import eu.europa.ec.eudi.verifier.endpoint.port.input.GetRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.input.GetRequestObjectLive
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransaction
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionLive
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateTransactionId
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.support.GenericApplicationContext
import org.springframework.core.annotation.AliasFor
import org.springframework.core.io.ClassPathResource
import org.springframework.test.context.ContextConfiguration
import java.security.KeyStore
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*
import kotlin.reflect.KClass

object TestContext {
    private val testDate = LocalDate.of(1974, 11, 2).atTime(10, 5, 33)
    val testClock = Clock.fixed(testDate.toInstant(ZoneOffset.UTC), ZoneOffset.UTC)
    val testTransactionId = TransactionId("SampleTxId")
    private val generatedTransactionId = GenerateTransactionId.fixed(testTransactionId)
    val testRequestId = RequestId("SampleRequestId")
    private val generateRequestId = GenerateRequestId.fixed(testRequestId)
    private val rsaJwk = run {
        ClassPathResource("test-cert.jks").inputStream.use {
            val keystore = KeyStore.getInstance("JKS").apply {
                load(it, "".toCharArray())
            }
            RSAKey.load(keystore, "client-id", "".toCharArray())
        }
    }

    val clientMetaData = ClientMetaData(
        jwkOption = ByValue,
        idTokenSignedResponseAlg = JWSAlgorithm.RS256.name,
        idTokenEncryptedResponseAlg = JWEAlgorithm.RSA_OAEP_256.name,
        idTokenEncryptedResponseEnc = EncryptionMethod.A128CBC_HS256.name,
        subjectSyntaxTypesSupported = listOf("urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key"),
        jarmOption = ParseJarmOptionNimbus(null, JWEAlgorithm.ECDH_ES.name, "A256GCM")!!,
    )
    val jarSigningConfig: SigningConfig = SigningConfig(rsaJwk, JWSAlgorithm.RS256)
    val clientIdScheme = ClientIdScheme.X509SanDns("client-id", jarSigningConfig)
    val singRequestObject: SignRequestObjectNimbus = SignRequestObjectNimbus()
    val singRequestObjectVerifier = RSASSAVerifier(rsaJwk)
    private val repo = PresentationInMemoryRepo()
    val loadPresentationById = repo.loadPresentationById
    val loadPresentationByRequestId = repo.loadPresentationByRequestId
    val storePresentation = repo.storePresentation
    val generateEphemeralKey = GenerateEphemeralEncryptionKeyPairNimbus

    fun initTransaction(
        verifierConfig: VerifierConfig,
        requestJarByReference: EmbedOption.ByReference<RequestId>,
        presentationDefinitionByReference: EmbedOption.ByReference<RequestId>,
        zkpOption: EmbedOption.ByReference<RequestId>,
    ): InitTransaction =
        InitTransactionLive(
            generatedTransactionId,
            generateRequestId,
            storePresentation,
            singRequestObject,
            verifierConfig,
            testClock,
            generateEphemeralKey,
            requestJarByReference,
            presentationDefinitionByReference,
            CreateQueryWalletResponseRedirectUri.Simple,
            zkpOption,

        )

    fun getRequestObject(verifierConfig: VerifierConfig, presentationInitiatedAt: Instant): GetRequestObject =
        GetRequestObjectLive(
            loadPresentationByRequestId,
            storePresentation,
            singRequestObject,
            verifierConfig,
            Clock.fixed(presentationInitiatedAt.plusSeconds(1 * 60), testClock.zone),
        )
}

/**
 * Meta annotation to be used with integration tests of [PidIssuerApplication].
 */
@Target(AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@SpringBootTest(
    classes = [VerifierApplication::class],
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "ISSUER_CERT=MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf/7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2/J0WVeghyw+mIwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr+ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW/U/5S5vAEC5XxcOanusOBroBbU=",
    ],
)
@ContextConfiguration(initializers = [BeansDslApplicationContextInitializer::class])
internal annotation class VerifierApplicationTest(

    /**
     * [Configuration] classes that contain extra bean definitions.
     * Useful for bean overriding using [Primary] annotation.
     */
    @get:AliasFor(annotation = ContextConfiguration::class)
    val classes: Array<KClass<*>> = [],

)

/**
 * [ApplicationContextInitializer] for use with [SpringBootTest]/[ContextConfiguration]
 */
internal class BeansDslApplicationContextInitializer : ApplicationContextInitializer<GenericApplicationContext> {
    override fun initialize(applicationContext: GenericApplicationContext) {
        beans(Clock.systemDefaultZone()).initializer().initialize(applicationContext)
    }
}
