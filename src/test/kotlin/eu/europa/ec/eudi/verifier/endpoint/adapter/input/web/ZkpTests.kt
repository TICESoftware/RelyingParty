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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import arrow.core.Some
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.prex.*
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.eq
import org.mockito.kotlin.whenever
import software.tice.VpTokenFormat
import software.tice.ZKPVerifier
import java.net.URI
import java.net.URL
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.assertEquals

class ZkpTests {
    @Mock
    private lateinit var loadPresentationByRequestId: LoadPresentationByRequestId

    @Mock
    private lateinit var storePresentation: StorePresentation

    @Mock
    private lateinit var verifyJarmJwtSignature: VerifyJarmJwtSignature

    @Mock
    private lateinit var verifierConfig: VerifierConfig

    @Mock
    private lateinit var getIssuerEcKey: ECKey

    @Mock
    private lateinit var zkpVerifier: ZKPVerifier

    private lateinit var postWalletResponseLive: PostWalletResponseLive
    private lateinit var privateKey: ECPrivateKey
    private lateinit var zkpKeys: ConcurrentHashMap<String, ECPrivateKey>
    private lateinit var presentation: RequestObjectRetrieved

    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)

        // Mock time
        val fixedInstant = Instant.parse("2023-01-01T00:00:00Z")
        val fixedClock = Clock.fixed(fixedInstant, ZoneId.of("UTC"))

        // generate fixed response code
        val fixedResponseCode = ResponseCode("test")
        val generateResponseCode: GenerateResponseCode = GenerateResponseCode.fixed(fixedResponseCode)

        // Override CreateQueryWalletResponseRedirectUri for the test
        val createQueryWalletResponseRedirectUri = object : CreateQueryWalletResponseRedirectUri {
            override fun redirectUri(template: String, responseCode: ResponseCode): Result<URL> = runCatching {
                URI(
                    template.replace(
                        CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER,
                        responseCode.value,
                    ),
                ).toURL()
            }

            override fun GetWalletResponseMethod.Redirect.redirectUri(responseCode: ResponseCode): URL =
                redirectUri(redirectUriTemplate, responseCode).getOrThrow()
        }

        postWalletResponseLive = PostWalletResponseLive(
            loadPresentationByRequestId,
            storePresentation,
            verifyJarmJwtSignature,
            fixedClock,
            verifierConfig,
            generateResponseCode,
            createQueryWalletResponseRedirectUri,
            getIssuerEcKey,
            zkpVerifier,
        )

        // Generate KeyPair for zkp
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
        privateKey = keyPair.private as ECPrivateKey
        val hashMapkeys: ConcurrentHashMap<String, ECPrivateKey> = ConcurrentHashMap()
        hashMapkeys["1"] = privateKey
        zkpKeys = ConcurrentHashMap<String, ECPrivateKey>().apply {
            put("id", privateKey)
        }

        // mock presentation
        val transactionId = TransactionId("transactionId")
        val instant = Instant.now()
        val presentationType: PresentationType = PresentationType.IdAndVpToken(
            idTokenType = listOf(IdTokenType.SubjectSigned),
            presentationDefinition = PresentationDefinition(
                name = null,
                id = Id("id"),
                inputDescriptors = listOf(
                    InputDescriptor(constraints = Constraints.LimitDisclosure.PREFERRED, id = InputDescriptorId("id")),
                ),
            ),
        )
        val redirectUriTemplate =
            "http://localhost:0/wallet-redirect#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}"
        val requestId = RequestId("requestId")
        val nonce = Nonce("nonce")
        val responseMode = ResponseModeOption.DirectPost

        presentation = RequestObjectRetrieved(
            id = transactionId,
            initiatedAt = instant,
            type = presentationType,
            requestId = requestId,
            requestObjectRetrievedAt = instant,
            nonce = nonce,
            ephemeralEcPrivateKey = null,
            responseMode = responseMode,
            getWalletResponseMethod = GetWalletResponseMethod.Redirect(redirectUriTemplate),
            zkpKeys = zkpKeys,
        )
    }

    @Test
    fun `should call zkpVerifier verifyChallenge for vc+sd-jwt+zkp format`() = runTest {
        val jsonContent = TestUtils.loadResource("02-presentationSubmissionSdJwtZkp.json")
        val presentationSubmission = Json.decodeFromString<PresentationSubmission>(jsonContent)

        val authorizationResponse = AuthorisationResponse.DirectPost(
            AuthorisationResponseTO(
                idToken = "idToken",
                state = "state",
                vpToken = "vpToken",
                presentationSubmission = presentationSubmission,
            ),
        )

        whenever(loadPresentationByRequestId.invoke(RequestId("state"))).thenReturn(presentation)
        whenever(zkpVerifier.verifyChallenge(eq(VpTokenFormat.SDJWT), eq("vpToken"), eq(privateKey))).thenReturn(true)

        val result = postWalletResponseLive.invoke(authorizationResponse)

        verify(zkpVerifier).verifyChallenge(
            eq(VpTokenFormat.SDJWT),
            eq("vpToken"),
            eq(privateKey),
        )
        assert(result is Some, { "Expected result to be Some, but was None" })
        result.fold({ fail("Expected Some, but was None") }, { acceptedTO ->
            assertEquals(
                "http://localhost:0/wallet-redirect#response_code=test",
                acceptedTO.redirectUri,
                "Redirect URI does not match expected value",
            )
        })
    }

    @Test
    fun `should call zkpVerifier verifyChallenge for mso_mdoc-jwt+zkp format`() = runTest {
        val jsonContent = TestUtils.loadResource("02-presentationSubmissionMdocZkp.json")
        val presentationSubmission = Json.decodeFromString<PresentationSubmission>(jsonContent)

        val json = TestUtils.loadResource("02-vpTokenMdoc.json")
        val vpToken = Json.decodeFromString<String>(json)

        val authorizationResponse = AuthorisationResponse.DirectPost(
            AuthorisationResponseTO(
                idToken = "idToken",
                state = "state",
                vpToken = vpToken,
                presentationSubmission = presentationSubmission,
            ),
        )

        whenever(loadPresentationByRequestId.invoke(RequestId("state"))).thenReturn(presentation)
        whenever(zkpVerifier.verifyChallenge(eq(VpTokenFormat.MSOMDOC), anyString(), eq(privateKey))).thenReturn(true)

        val result = postWalletResponseLive.invoke(authorizationResponse)

        verify(zkpVerifier).verifyChallenge(
            eq(VpTokenFormat.MSOMDOC),
            anyString(),
            eq(privateKey),
        )

        assert(result is Some, { "Expected result to be Some, but was None" })
        result.fold({ fail("Expected Some, but was None") }, { acceptedTO ->
            assertEquals(
                "http://localhost:0/wallet-redirect#response_code=test",
                acceptedTO.redirectUri,
                "Redirect URI does not match expected value",
            )
        })
    }
}
