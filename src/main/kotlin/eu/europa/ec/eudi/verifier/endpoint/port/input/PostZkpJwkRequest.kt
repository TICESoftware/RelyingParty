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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.raise.Raise
import arrow.core.raise.ensure
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.awaitBody
import software.tice.ChallengeRequestData
import software.tice.ZKPVerifier
import java.security.interfaces.ECPrivateKey
import java.util.*
import java.util.concurrent.ConcurrentHashMap

sealed interface ZkpJwkError {
    data object ProcessingError : ZkpJwkError
}

data class ChallengeRequest(
    val id: String,
    val digest: String,
    val r: String,
    val proofType: String,
)

data class EphemeralKeyResponse(
    val id: String,
    val kid: String,
    val kty: String,
    val crv: String,
    val x: String,
    val y: String,
)

/**
 * Given a [RequestId] and [ServerRequest] returns a list of ephemeral public keys derived from the input data (digest and r) for the ZKP.
 */

fun interface PostZkpJwkRequest {
    context(Raise<ZkpJwkError>)
    suspend operator fun invoke(request: ServerRequest, requestId: RequestId): List<EphemeralKeyResponse>
}

class PostZkpJwkRequestLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val getIssuerEcKey: ECKey,
    private val zkpKeys: ConcurrentHashMap<String, ECPrivateKey> = ConcurrentHashMap(),
) : PostZkpJwkRequest {
    val logger: Logger = LoggerFactory.getLogger(PostWalletResponseLive::class.java)

    context(Raise<ZkpJwkError>)
    override suspend operator fun invoke(request: ServerRequest, requestId: RequestId): List<EphemeralKeyResponse> {
        val verifier = ZKPVerifier(getIssuerEcKey.toECPublicKey())
        val presentation = loadPresentationByRequestId(requestId)
        val challengeRequests = request.awaitBody<Array<ChallengeRequest>>()

        val ephemeralKeyResponses = challengeRequests.map { challengeRequest ->
            val challengeRequestData = ChallengeRequestData(digest = challengeRequest.digest, r = challengeRequest.r)
            val (challenge, key) = verifier.createChallenge(challengeRequestData)
            zkpKeys[challengeRequest.id] = key

            val x = challenge.w.affineX.toString()
            val y = challenge.w.affineY.toString()

            val base64EncodedX = Base64.getUrlEncoder().encodeToString(x.toByteArray())
            val base64EncodedY = Base64.getUrlEncoder().encodeToString(y.toByteArray())

            EphemeralKeyResponse(
                id = challengeRequest.id,
                kid = challengeRequest.id,
                kty = "EC",
                crv = "P-256",
                x = base64EncodedX,
                y = base64EncodedY,
            )
        }

        if (presentation != null) {
            ensure(presentation is RequestObjectRetrieved) { raise(ZkpJwkError.ProcessingError) }
            val updatedPresentation = presentation.copy(zkpKeys = zkpKeys)
            storePresentation(updatedPresentation)
            logger.info("updatedPresentation $updatedPresentation")
        }
        // TODO: check if zkpKeys is saved properly
        return ephemeralKeyResponses
    }
}
