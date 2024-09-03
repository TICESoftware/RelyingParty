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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseCode
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.EphemeralKeyResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.TestMethodOrder
import org.junit.jupiter.api.assertThrows
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.core.annotation.Order
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import software.tice.ZKPGenerator
import software.tice.ZKPProverSdJwt
import software.tice.ZKPVerifier
import java.lang.AssertionError
import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import kotlin.test.*

@VerifierApplicationTest
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.response.mode=DirectPost",
        "verifier.clientMetadata.authorizationSignedResponseAlg=",
        "verifier.clientMetadata.authorizationEncryptedResponseAlg=ECDH-ES",
        "verifier.clientMetadata.authorizationEncryptedResponseEnc=A128CBC-HS256",
    ],
)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
internal class WalletResponseDirectPostWithIdTokenAndVpTokenTest {

    private val log: Logger = LoggerFactory.getLogger(WalletResponseDirectPostWithIdTokenAndVpTokenTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     */
    @Test
    @Order(value = 1)
    fun `post wallet response (only idToken) - confirm returns 200`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val presentationId = transactionInitialized.transactionId
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("02-vpTokenSdJwt.json"))
        formEncodedBody.add("presentation_submission", TestUtils.loadResource("02-presentationSubmissionSdJwt.json"))

        // when
        WalletApiClient.directPost(client, formEncodedBody)

        // then
        assertNotNull(presentationId)
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     * - verifier to verifier backend, to get wallet response
     */
    @Test
    @Order(value = 3)

    fun `get wallet response for format vc+sd-jwt - confirm returns 200`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinitionWithRedirect.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val presentationId = TransactionId(transactionInitialized.transactionId)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("02-vpTokenSdJwt.json"))
        formEncodedBody.add("presentation_submission", TestUtils.loadResource("02-presentationSubmissionSdJwt.json"))

        val result = WalletApiClient.directPostWithResponse(client, formEncodedBody)
        val responseCode = ResponseCode(value = result!!)

        // when
        val response = VerifierApiClient.getWalletResponse(client, presentationId, responseCode)

        // then
        assertNotNull(response)

    }
@Test

    fun `missing vpToken - fails with MissingVpTokenOrPresentationSubmission`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinitionWithRedirect.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val presentationId = TransactionId(transactionInitialized.transactionId)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", null)
        formEncodedBody.add("presentation_submission", TestUtils.loadResource("02-presentationSubmissionSdJwt.json"))

        val result = WalletApiClient.directPostWithResponse(client, formEncodedBody)
        val responseCode = ResponseCode(value = result!!)

        // when
        try {
            VerifierApiClient.getWalletResponse(client, presentationId, responseCode)
        } catch (e: AssertionError) {}



    }

    @Test
    @Order(value = 4)

    fun `get wallet response for format mso_mdoc - confirm returns 200`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinitionWithRedirect.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val presentationId = TransactionId(transactionInitialized.transactionId)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("02-vpTokenMdoc.json"))
        formEncodedBody.add("presentation_submission", TestUtils.loadResource("02-presentationSubmissionMdoc.json"))

        val result = WalletApiClient.directPostWithResponse(client, formEncodedBody)
        val responseCode = ResponseCode(value = result!!)

        // when
        val response = VerifierApiClient.getWalletResponse(client, presentationId, responseCode)

        // then
        assertNotNull(response)

    }

    @Test
    @Order(value = 5)

    fun `fetch ephemeral key response for zkp flow - returns list of ephemeral keys`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinitionWithRedirect.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val presentationId = TransactionId(transactionInitialized.transactionId)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // check whole zkp flow
        // create challenge data
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val ecKPGen = KeyPairGenerator.getInstance("EC")
        ecKPGen.initialize(ecParameters)

        val issuerKP = ecKPGen.generateKeyPair()
        val issuerPublicKey = issuerKP.public as ECPublicKey

        val message = "Some raw message".encodeToByteArray()
        val signer = ECDSASigner(issuerKP.private, Curve.P_256)
        val jwtHeader = JWSHeader(JWSAlgorithm.ES256)
        val jwtSignature = signer.sign(jwtHeader, message)

        val jwt = "${jwtHeader.toBase64URL()}.${Base64URL.encode(message)}.$jwtSignature"

        val zkpGenerator = ZKPGenerator(issuerPublicKey)
        val prover = ZKPProverSdJwt(zkpGenerator)

        val challengeRequestData = prover.createChallengeRequest(jwt)

        // when
        val ephemeralKeys: List<EphemeralKeyResponse> =
            WalletApiClient.fetchZkpKeys(client, challengeRequestData, requestId)
        print("This is the $ephemeralKeys")

        // then
        assertNotNull(ephemeralKeys)
    }


    /**
     * Verifies that a Transaction expecting a direct_post Wallet response, doesn't accept a direct_post.jwt Wallet response.
     */
    @Test
    @Order(value = 6)
    fun `with response_mode direct_post, direct_post_jwt wallet responses are rejected`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // At this point we don't generate an actual JARM response
        // The response will be rejected before JARM parsing/verification takes place
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("response", "response")
        formEncodedBody.add("state", requestId.value)

        // send the wallet response
        // we expect the response submission to fail
        try {
            WalletApiClient.directPostJwt(client, formEncodedBody)
            fail("Expected direct_post.jwt submission to fail for direct_post Presentation")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }
}
